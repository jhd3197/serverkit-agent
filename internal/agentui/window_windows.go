//go:build windows

package agentui

import (
	"context"
	"fmt"
	"os"
	"runtime"
	"time"

	webview2 "github.com/jchv/go-webview2"

	"github.com/jhd3197/serverkit-agent/internal/logger"
)

// Run launches the agent's WebView2 console window and blocks until the user
// closes it. configPath is reserved for the upcoming wizard-migration
// milestone — for now the React app loads in console-only mode and the
// existing setupui wizard still owns first-run pairing.
//
// Set SERVERKIT_AGENT_UI_DEV=http://localhost:5174 to point the webview at
// the Vite dev server instead of the embedded bundle. Useful while iterating
// on the UI: changes hot-reload without rebuilding the Go binary.
//
// Set SERVERKIT_AGENT_UI_DEVTOOLS=false to disable DevTools. By default the
// 1.6.2 console ships with DevTools enabled so blank-page reports come with
// a way for the user to press F12 and capture errors.
func Run(ctx context.Context, log *logger.Logger, configPath string) error {
	runtime.LockOSThread()

	log.Info("agentui.Run: starting")

	// Preflight: bail with a clear error before constructing the webview.
	// Skipping this leads to "blank window" reports when the runtime is
	// missing — go-webview2 doesn't always return nil on failure.
	if v := detectWebView2(); v == "" {
		log.Error("agentui.Run: WebView2 runtime not detected")
		return fmt.Errorf(
			"WebView2 runtime not installed. " +
				"Download the Evergreen Bootstrapper from " +
				"https://developer.microsoft.com/microsoft-edge/webview2/ and re-run setup",
		)
	} else {
		log.Info("agentui.Run: WebView2 runtime detected", "version", v)
	}

	target := os.Getenv("SERVERKIT_AGENT_UI_DEV")
	var stopServer func()
	if target == "" {
		log.Info("agentui.Run: starting embedded asset server")
		url, shutdown, err := startAssetServer(ctx, log, configPath)
		if err != nil {
			log.Error("agentui.Run: asset server failed", "error", err)
			return fmt.Errorf("start asset server: %w", err)
		}
		log.Info("agentui.Run: asset server up", "url", url)
		target = url
		stopServer = shutdown
	} else {
		// Even in dev mode we still need the action/pair endpoints — the
		// Vite dev server only serves UI assets. Start the asset server
		// alongside it; dev UI fetches the local API by absolute origin.
		_, shutdown, err := startAssetServer(ctx, log, configPath)
		if err != nil {
			return fmt.Errorf("start asset server: %w", err)
		}
		stopServer = shutdown
		log.Info("agentui.Run: using dev server", "url", target)
	}
	if stopServer != nil {
		defer stopServer()
	}

	// 1.6.1 reports said: blank white window, no errors. We could not see
	// what the React app was doing because the only diagnostic was the Go
	// log on the host side. 1.6.2 ships with DevTools enabled by default so
	// users can press F12 and screenshot errors. Set the env var to "false"
	// to turn it off in installs where security policy prohibits it.
	devtools := os.Getenv("SERVERKIT_AGENT_UI_DEVTOOLS") != "false"
	log.Info("agentui.Run: constructing WebView2 window", "devtools", devtools)
	w := webview2.NewWithOptions(webview2.WebViewOptions{
		Debug:     devtools,
		AutoFocus: true,
		WindowOptions: webview2.WindowOptions{
			Title: "ServerKit Agent",
			// Sidebar is 220px; content area at 1200x800 lands at 980x800
			// which gives the Overview metric cards and the Logs/Activity
			// timeline room to breathe without horizontal scrollbars.
			Width:  1200,
			Height: 800,
			IconId: 2,
			Center: true,
		},
	})
	if w == nil {
		log.Error("agentui.Run: webview2.NewWithOptions returned nil")
		return fmt.Errorf("webview2 init failed; the runtime may be present but blocked by group policy or AV")
	}
	defer w.Destroy()

	// Bridge JS console + window errors back to the Go log so 1.6.2 doesn't
	// leave us blind on blank-page reports. The page calls these via
	// window.agentLog / window.agentNavReady, which Init() wires up below.
	if err := w.Bind("agentLog", func(level, msg string) {
		switch level {
		case "error":
			log.Error("ui.js: " + msg)
		case "warn":
			log.Warn("ui.js: " + msg)
		default:
			log.Info("ui.js: " + msg)
		}
		return
	}); err != nil {
		log.Warn("agentui.Run: Bind agentLog failed", "error", err)
	}
	navReady := make(chan struct{}, 1)
	if err := w.Bind("agentNavReady", func(href string) {
		log.Info("ui.js: navigation ready", "href", href)
		select {
		case navReady <- struct{}{}:
		default:
		}
		return
	}); err != nil {
		log.Warn("agentui.Run: Bind agentNavReady failed", "error", err)
	}

	// Inject a tiny shim *before* the React bundle runs. It forwards every
	// console.error / unhandledrejection / window.onerror through agentLog,
	// and pings agentNavReady once the document has parsed. This is what
	// fills the gap that NavigationCompleted would have filled if the
	// upstream library exposed it on the public WebView interface.
	w.Init(`
		(function() {
		    var safe = function(fn) { try { fn(); } catch (e) {} };
		    var send = function(level, msg) {
		        if (window.agentLog) safe(function(){ window.agentLog(level, String(msg)); });
		    };
		    safe(function(){
		        var origErr = console.error;
		        console.error = function() {
		            send('error', Array.prototype.slice.call(arguments).map(String).join(' '));
		            return origErr.apply(console, arguments);
		        };
		    });
		    window.addEventListener('error', function(ev) {
		        send('error', (ev.message || 'window.onerror') + ' @ ' + (ev.filename||'?') + ':' + (ev.lineno||0));
		    });
		    window.addEventListener('unhandledrejection', function(ev) {
		        var r = ev && ev.reason;
		        send('error', 'unhandledrejection: ' + (r && r.message ? r.message : String(r)));
		    });
		    var ready = function() {
		        if (window.agentNavReady) safe(function(){ window.agentNavReady(location.href); });
		    };
		    if (document.readyState === 'complete' || document.readyState === 'interactive') {
		        setTimeout(ready, 0);
		    } else {
		        document.addEventListener('DOMContentLoaded', ready);
		    }
		    send('info', 'agent shim installed, ua=' + navigator.userAgent);
		})();
	`)

	w.SetSize(900, 600, webview2.HintMin)

	// Hide the host window immediately so the user never sees WebView2's
	// pre-paint white rectangle or the dark-CSS-but-pre-React black gap.
	// We re-show in forceForeground once navReady fires (or 3s elapses as
	// a safety net for cases where the JS shim never installs).
	hideHostWindow(w.Window())

	log.Info("agentui.Run: navigating", "url", target)
	w.Navigate(target)

	// Reveal the window the moment the bundle reports ready. The 3s
	// fallback is deliberately generous: on cold-start machines, WebView2
	// can take ~1.5s to hydrate the first paint, and we'd rather show a
	// real (if late) UI than show a flash. The 8s mark logs a louder
	// warning so blank-page reports have a clear breadcrumb.
	go func() {
		select {
		case <-navReady:
			log.Info("agentui.Run: UI bundle reported ready, showing window")
			forceForeground(w.Window())
		case <-time.After(3 * time.Second):
			log.Warn("agentui.Run: no UI ready signal after 3s; revealing window anyway")
			forceForeground(w.Window())
			select {
			case <-navReady:
				log.Info("agentui.Run: UI bundle reported ready (after fallback)")
			case <-time.After(5 * time.Second):
				log.Warn("agentui.Run: no UI ready signal after 8s; bundle likely failed (right-click → Inspect to debug)")
			case <-ctx.Done():
			}
		case <-ctx.Done():
			return
		}
	}()

	// Hook ctx cancellation to terminate the webview from a background
	// goroutine. Run() blocks on the OS message pump, so we need an external
	// signal to break it cleanly when the parent process is torn down.
	go func() {
		<-ctx.Done()
		log.Info("agentui.Run: ctx cancelled, terminating webview")
		w.Terminate()
	}()

	log.Info("agentui.Run: entering message loop (w.Run)")
	w.Run()
	log.Info("agentui.Run: message loop exited cleanly")
	return nil
}

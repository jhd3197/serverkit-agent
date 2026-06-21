package agentui

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"time"

	"github.com/jhd3197/serverkit-agent/internal/logger"
)

// startAssetServer binds an HTTP server to a free 127.0.0.1 port and serves
// the embedded UI bundle from it. WebView2 then navigates to the resulting
// URL — using a real HTTP origin (rather than file:// or a virtual host
// mapping) means relative imports, fetch(), and the dev tools "Network"
// panel all behave the same as when running the dev server, which keeps
// surprises out of the migration. Returns the URL to navigate to and a
// shutdown func that stops the server cleanly.
func startAssetServer(ctx context.Context, log *logger.Logger, configPath string) (url string, shutdown func(), err error) {
	dist, err := distFS()
	if err != nil {
		return "", nil, fmt.Errorf("load embedded ui: %w", err)
	}

	// Bind to :0 so the OS hands us an unused port; we don't conflict with
	// the agent's IPC server (19780) or any panel running locally.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", nil, fmt.Errorf("bind asset server: %w", err)
	}

	mux := http.NewServeMux()
	newLocalActions(configPath).register(mux)
	newPairer(log, configPath).register(mux)

	// Wrap the static file server with no-store headers. WebView2 caches
	// per-user-data-folder aggressively; on an MSI upgrade the new bundle
	// would otherwise be shadowed by the previous index.html for several
	// runs. Asset payload is ~600KB total, so loading it fresh each launch
	// has no perceptible cost and removes a whole class of stale-asset
	// bug reports.
	noCache := func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
			w.Header().Set("Pragma", "no-cache")
			w.Header().Set("Expires", "0")
			h.ServeHTTP(w, r)
		})
	}
	mux.Handle("/", noCache(http.FileServer(http.FS(dist))))

	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	go func() {
		_ = srv.Serve(ln)
	}()

	addr := ln.Addr().(*net.TCPAddr)
	url = fmt.Sprintf("http://127.0.0.1:%d/", addr.Port)

	shutdown = func() {
		ctxShut, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctxShut)
	}

	return url, shutdown, nil
}

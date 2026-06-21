// Package agentui hosts the ServerKit agent's desktop console: a WebView2
// window driven by an embedded React SPA. It coexists with the legacy walk
// pairing wizard in setupui — the wizard handles first-run pairing today,
// and this package owns the post-pair "running app" experience that the
// tray previously delegated to a few menu items. Over the next milestones
// the wizard migrates here too so there's one window for everything.
package agentui

import (
	"embed"
	"io/fs"
)

// uiDist is the built React app from agent/ui/dist. The Makefile / CI must
// run `npm run build` in that folder before `go build`, otherwise the
// embed below fails at compile time. We accept that hard-fail so a release
// can never accidentally ship a stale or empty UI bundle.
//
//go:embed all:dist
var uiDist embed.FS

// distFS returns the embedded UI rooted at the dist/ directory so the HTTP
// server can serve "/" → "dist/index.html" without leaking the dist prefix
// into URLs.
func distFS() (fs.FS, error) {
	return fs.Sub(uiDist, "dist")
}

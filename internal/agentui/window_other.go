//go:build !windows

package agentui

import (
	"context"
	"fmt"

	"github.com/jhd3197/serverkit-agent/internal/logger"
)

// Run is a stub on non-Windows platforms; the WebView2-based console is
// Windows-only for now. macOS / Linux desktop console support arrives once
// the wizard migration is done and we pick a cross-platform webview wrapper.
func Run(_ context.Context, _ *logger.Logger, _ string) error {
	return fmt.Errorf("the agent console window is only available on Windows")
}

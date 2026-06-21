//go:build !windows

package setupui

import (
	"context"
	"fmt"

	"github.com/jhd3197/serverkit-agent/internal/logger"
)

// runWindow returns an error directing non-Windows users to the CLI command.
// The desktop wizard is Windows-only because it uses native Win32 controls.
func runWindow(_ context.Context, _ *logger.Logger, _ string) error {
	return fmt.Errorf("the graphical setup wizard is only available on Windows; on this platform run: serverkit-agent pair")
}

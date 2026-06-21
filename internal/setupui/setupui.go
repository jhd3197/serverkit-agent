// Package setupui shows the legacy native-walk pairing wizard. The pairing
// protocol itself moved to internal/pairdriver so both this wizard and the
// React-based agentui console can drive it.
package setupui

import (
	"context"

	"github.com/jhd3197/serverkit-agent/internal/config"
	"github.com/jhd3197/serverkit-agent/internal/logger"
)

// Run shows the pairing wizard and blocks until the user closes it.
// configPath may be empty to use the default location.
func Run(ctx context.Context, log *logger.Logger, configPath string) error {
	if configPath == "" {
		configPath = config.DefaultConfigPath()
	}
	return runWindow(ctx, log.WithComponent("setupui"), configPath)
}

// Package gui implements the agent's GUI/desktop capability bridge.
//
// This is a deliberately small SDK that any panel-side extension can lean on
// without forcing the agent to fork: the agent owns *how* a screenshot is
// captured on each platform, and exposes a stable JSON contract through the
// gui:screenshot and gui:capabilities actions. Plugins (e.g. serverkit-gui)
// only deal with the contract — they never ship binaries to the agent.
//
// Implementation note: the platform paths shell out to OS-built-in tools
// (PowerShell's System.Drawing on Windows, scrot/grim/import on Linux). This
// keeps the agent dep-free and dodges cgo, at the cost of ~200ms per frame on
// Windows. A native fast path (kbinani/screenshot) is a future optimization;
// at the 1–2 fps the streaming UI runs at, shell-out is comfortably fast
// enough.
package gui

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/jhd3197/serverkit-agent/internal/logger"
)

// Capabilities describes what the host can do for desktop capture.
type Capabilities struct {
	// Capability is one of: "windows-gdi", "linux-x11", "linux-wayland",
	// "macos-quartz", "none". Plugins gate behavior on this string.
	Capability string `json:"capability"`

	// Resolution is "WxH" of the primary display, when known.
	Resolution string `json:"resolution,omitempty"`

	// MaxFPS is what the agent recommends as a sane upper bound. The
	// panel may run slower; it should not run faster.
	MaxFPS int `json:"max_fps"`

	// SyntheticFallback hints to the panel that no real capture is
	// possible and it should render its synthetic UI mode.
	SyntheticFallback bool `json:"synthetic_fallback"`

	// Reason explains why Capability is "none", when applicable.
	Reason string `json:"reason,omitempty"`
}

// ScreenshotParams are the per-frame knobs the panel can dial.
type ScreenshotParams struct {
	// Scale 0 < s <= 1 — server-side downscale before encoding.
	Scale float64 `json:"scale"`
	// Quality 10..95 for JPEG; ignored for PNG.
	Quality int `json:"quality"`
	// Format "jpeg" or "png". JPEG is smaller; PNG preserves text.
	Format string `json:"format"`
}

// Frame is what we hand back. ImageBase64 is the encoded image; the rest is
// metadata so the UI can size and timestamp the frame without decoding.
type Frame struct {
	ImageBase64 string `json:"image_base64"`
	Format      string `json:"format"`
	Width       int    `json:"width"`
	Height      int    `json:"height"`
	CapturedAt  string `json:"captured_at"`
}

// SDK is the agent-side capability bridge. One instance per agent process.
type SDK struct {
	log *logger.Logger
}

// New returns an initialized SDK.
func New(log *logger.Logger) *SDK {
	return &SDK{log: log}
}

// HandleCapabilities — wired to protocol.ActionGUICapabilities.
func (s *SDK) HandleCapabilities(_ context.Context, _ json.RawMessage) (interface{}, error) {
	c, err := detectCapabilities()
	if err != nil {
		// Capability detection isn't supposed to fail loudly; downgrade
		// to a synthetic-fallback response so the UI degrades gracefully.
		return Capabilities{
			Capability:        "none",
			SyntheticFallback: true,
			Reason:            err.Error(),
		}, nil
	}
	return c, nil
}

// HandleScreenshot — wired to protocol.ActionGUIScreenshot.
func (s *SDK) HandleScreenshot(ctx context.Context, raw json.RawMessage) (interface{}, error) {
	params := ScreenshotParams{Scale: 0.75, Quality: 70, Format: "jpeg"}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &params); err != nil {
			return nil, fmt.Errorf("invalid params: %w", err)
		}
	}
	if params.Scale <= 0 || params.Scale > 1 {
		params.Scale = 0.75
	}
	if params.Quality < 10 || params.Quality > 95 {
		params.Quality = 70
	}
	if params.Format != "png" && params.Format != "jpeg" {
		params.Format = "jpeg"
	}

	frame, err := captureFrame(ctx, params)
	if err != nil {
		return nil, fmt.Errorf("capture: %w", err)
	}

	if s.log != nil {
		s.log.Info("gui:screenshot",
			"format", frame.Format,
			"width", frame.Width,
			"height", frame.Height,
			"bytes_b64", len(frame.ImageBase64),
		)
	}
	return frame, nil
}

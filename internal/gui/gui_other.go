//go:build !windows && !linux

package gui

import "context"

func detectCapabilities() (Capabilities, error) {
	return Capabilities{
		Capability:        "none",
		SyntheticFallback: true,
		Reason:            "platform not yet supported by gui SDK",
	}, nil
}

func captureFrame(_ context.Context, _ ScreenshotParams) (*Frame, error) {
	return nil, errNotImplemented
}

var errNotImplemented = &platformErr{"gui capture not implemented on this platform"}

type platformErr struct{ msg string }

func (e *platformErr) Error() string { return e.msg }

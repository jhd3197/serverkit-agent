//go:build !linux

package cron

import (
	"context"
	"fmt"
)

// New returns a stub Manager on non-Linux platforms. Every operation
// reports the feature as unavailable so callers fail loudly rather
// than silently doing nothing.
func New() Manager { return stubManager{} }

type stubManager struct{}

var errUnsupported = fmt.Errorf("cron is only supported on Linux agents")

func (stubManager) Status(ctx context.Context) (*Status, error) {
	return &Status{Available: false, Reason: "cron is only supported on Linux agents"}, nil
}
func (stubManager) List(ctx context.Context) ([]Entry, error)       { return nil, errUnsupported }
func (stubManager) Add(ctx context.Context, _ AddRequest) (*Entry, error) {
	return nil, errUnsupported
}
func (stubManager) Remove(ctx context.Context, _ string) error           { return errUnsupported }
func (stubManager) Toggle(ctx context.Context, _ string, _ bool) error   { return errUnsupported }

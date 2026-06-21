//go:build !linux

package cloudflared

import (
	"context"
	"fmt"
)

// New returns a stub Manager on non-Linux platforms.
func New() Manager { return stubManager{} }

type stubManager struct{}

var errUnsupported = fmt.Errorf("cloudflared is only supported on Linux agents")

func (stubManager) Status(ctx context.Context) (*Status, error) {
	return &Status{Available: false, Reason: "cloudflared is only supported on Linux agents"}, nil
}
func (stubManager) List(ctx context.Context) ([]Tunnel, error) { return nil, errUnsupported }
func (stubManager) Create(ctx context.Context, _ CreateRequest) (*Tunnel, error) {
	return nil, errUnsupported
}
func (stubManager) Route(ctx context.Context, _ RouteRequest) error { return errUnsupported }
func (stubManager) Delete(ctx context.Context, _ string) error      { return errUnsupported }
func (stubManager) Login(ctx context.Context) (<-chan LoginEvent, error) {
	return nil, errUnsupported
}

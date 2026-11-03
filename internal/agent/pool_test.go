package agent

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/jhd3197/serverkit-agent/internal/permissions"
	"github.com/jhd3197/serverkit-agent/pkg/protocol"
)

func TestSubmitCommandBoundedPool(t *testing.T) {
	a, ft := newLevelAgent(t, permissions.Full)
	a.cmdSlots = make(chan struct{}, 2)
	started := make(chan struct{}, 2)
	a.handlers[protocol.ActionSystemdStatus] = func(ctx context.Context, _ json.RawMessage) (interface{}, error) {
		started <- struct{}{}
		<-ctx.Done()
		return nil, ctx.Err()
	}
	slow := func(id string) []byte { return cmdJSON(id, protocol.ActionSystemdStatus) }

	start := time.Now()
	a.submitCommand(slow("1"))
	a.submitCommand(slow("2"))
	<-started
	<-started
	a.submitCommand(slow("3")) // pool full -> immediate busy reply
	if time.Since(start) > time.Second {
		t.Fatal("submitCommand blocked")
	}
	ft.mu.Lock()
	if len(ft.results) != 1 || ft.results[0].id != "3" || ft.results[0].ok {
		t.Fatalf("want busy result for 3, got %+v", ft.results)
	}
	ft.mu.Unlock()

	a.cmdCancel() // shutdown cancels workers, which then report
	a.cmdWG.Wait()
	ft.mu.Lock()
	defer ft.mu.Unlock()
	if len(ft.results) != 3 {
		t.Fatalf("want 3 results after drain, got %d", len(ft.results))
	}
}

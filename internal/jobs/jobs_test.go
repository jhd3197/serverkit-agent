package jobs

import (
	"strconv"
	"sync"
	"testing"
)

type recorder struct {
	mu   sync.Mutex
	sent []Event
}

func (r *recorder) SendStream(channel string, data interface{}) error {
	ev, _ := data.(Event)
	r.mu.Lock()
	r.sent = append(r.sent, ev)
	r.mu.Unlock()
	return nil
}

func TestRegistryNewAssignsUniqueChannel(t *testing.T) {
	r := NewRegistry(8)
	a := r.New(0)
	b := r.New(0)
	if a.ID == b.ID {
		t.Fatal("expected unique IDs")
	}
	if a.Channel != "job:"+a.ID || b.Channel != "job:"+b.ID {
		t.Fatalf("unexpected channels: %q %q", a.Channel, b.Channel)
	}
	if r.LookupByChannel(a.Channel) != a {
		t.Fatal("LookupByChannel did not round-trip")
	}
	if r.LookupByChannel("metrics") != nil {
		t.Fatal("non-job channel should return nil")
	}
}

func TestPushAndReplayPreserveOrder(t *testing.T) {
	r := NewRegistry(8)
	j := r.New(4)
	rec := &recorder{}

	for i := 0; i < 3; i++ {
		if err := j.Push(rec, Event{Phase: PhaseLog, Message: strconv.Itoa(i)}); err != nil {
			t.Fatal(err)
		}
	}
	got := j.Replay()
	if len(got) != 3 {
		t.Fatalf("want 3 events, got %d", len(got))
	}
	for i, ev := range got {
		if ev.Message != strconv.Itoa(i) {
			t.Fatalf("event %d out of order: %q", i, ev.Message)
		}
	}
	if len(rec.sent) != 3 {
		t.Fatalf("transport got %d events, want 3", len(rec.sent))
	}
}

func TestRingBufferDropsOldest(t *testing.T) {
	r := NewRegistry(8)
	j := r.New(3)
	rec := &recorder{}
	for i := 0; i < 5; i++ {
		_ = j.Push(rec, Event{Phase: PhaseLog, Message: strconv.Itoa(i)})
	}
	got := j.Replay()
	if len(got) != 3 {
		t.Fatalf("ring should hold 3 events, got %d", len(got))
	}
	// Oldest two events (0,1) should have been dropped; expect 2,3,4.
	for i, ev := range got {
		want := strconv.Itoa(i + 2)
		if ev.Message != want {
			t.Fatalf("ring order broken at %d: got %q want %q", i, ev.Message, want)
		}
	}
}

func TestDoneClosedOnTerminalEvent(t *testing.T) {
	r := NewRegistry(8)
	j := r.New(4)
	select {
	case <-j.Done():
		t.Fatal("done before terminal event")
	default:
	}
	exit := 0
	_ = j.Push(nil, Event{Phase: PhaseDone, ExitCode: &exit})
	select {
	case <-j.Done():
	default:
		t.Fatal("done not closed after terminal event")
	}
	// Idempotent: second done event must not panic.
	_ = j.Push(nil, Event{Phase: PhaseDone, ExitCode: &exit})
}

func TestRegistryEvictsOldestJobs(t *testing.T) {
	r := NewRegistry(2)
	j1 := r.New(0)
	j2 := r.New(0)
	j3 := r.New(0)
	if r.Get(j1.ID) != nil {
		t.Fatal("j1 should have been evicted")
	}
	if r.Get(j2.ID) == nil || r.Get(j3.ID) == nil {
		t.Fatal("j2/j3 should still be present")
	}
}

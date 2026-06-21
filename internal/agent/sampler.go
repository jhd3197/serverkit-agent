package agent

import (
	"context"
	"sync"
	"time"

	"github.com/jhd3197/serverkit-agent/internal/ipc"
)

// metricSampler maintains a fixed-size ring buffer of CPU and memory samples
// taken once per second. The agent's main metrics path (Collect → emit over
// the WebSocket) already pulls live values, but the desktop console needs a
// short-lived history to render sparklines without keeping a long-lived
// websocket of its own to the agent. 300 samples × 1 s = 5 minutes of
// scrollback, which matches the Overview tab design.
type metricSampler struct {
	mu      sync.Mutex
	samples []ipc.MetricSample
	cap     int
}

func newMetricSampler(capacity int) *metricSampler {
	return &metricSampler{
		samples: make([]ipc.MetricSample, 0, capacity),
		cap:     capacity,
	}
}

// push records one sample, evicting the oldest when the buffer is full.
func (s *metricSampler) push(sample ipc.MetricSample) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.samples) >= s.cap {
		copy(s.samples, s.samples[1:])
		s.samples = s.samples[:len(s.samples)-1]
	}
	s.samples = append(s.samples, sample)
}

// snapshot returns a copy of the current samples in chronological order so
// the caller can serialize them without holding the lock.
func (s *metricSampler) snapshot() []ipc.MetricSample {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]ipc.MetricSample, len(s.samples))
	copy(out, s.samples)
	return out
}

// samplerLoop runs until ctx is cancelled. Every tick it pulls one CPU/Mem
// sample from the agent's metrics collector and pushes it into the ring.
// Transient collection errors are swallowed: a one-tick gap is preferable
// to a stutter in the graph or a noisy log.
func (a *Agent) samplerLoop(ctx context.Context) {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if a.metrics == nil || a.sampler == nil {
				continue
			}
			collectCtx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
			sm, err := a.metrics.Collect(collectCtx)
			cancel()
			if err != nil {
				continue
			}
			a.sampler.push(ipc.MetricSample{
				Timestamp: time.Now().UnixMilli(),
				CPU:       sm.CPUPercent,
				Mem:       sm.MemoryPercent,
			})
		}
	}
}

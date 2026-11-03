package ws

import (
	"testing"
	"time"
)

func TestNextBackoff(t *testing.T) {
	base, max := 5*time.Second, time.Minute
	mid := func() float64 { return 0.5 } // factor 1.0
	hi := func() float64 { return 0.999999 }
	lo := func() float64 { return 0 }

	prev := time.Duration(0)
	for a := 1; a <= 20; a++ {
		d := nextBackoff(a, base, max, mid)
		if d < prev {
			t.Fatalf("attempt %d: %v < %v", a, d, prev)
		}
		prev = d
	}
	if prev != max {
		t.Fatalf("cap = %v, want %v", prev, max)
	}
	if got := nextBackoff(1, base, max, mid); got != base {
		t.Fatalf("attempt 1 = %v", got)
	}
	if got := nextBackoff(3, base, max, mid); got != 20*time.Second {
		t.Fatalf("attempt 3 = %v", got)
	}
	for _, a := range []int{0, -5, 1, 7, 63, 64, 1000, 1 << 30} {
		for _, r := range []func() float64{lo, mid, hi} {
			d := nextBackoff(a, base, max, r)
			if d <= 0 || d > time.Duration(float64(max)*1.2) || d < time.Duration(float64(base)*0.8) {
				t.Fatalf("attempt %d: %v out of range", a, d)
			}
		}
	}
	// huge base must not overflow either
	if d := nextBackoff(1000, time.Hour, 5*time.Hour, hi); d <= 0 || d > 6*time.Hour {
		t.Fatalf("got %v", d)
	}
}

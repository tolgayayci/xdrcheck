package conform

import (
	"testing"
	"time"
)

// The per-request timeout scales with the input: the base for a small value, once more per MiB of a ledger.
func TestRequestTimeout(t *testing.T) {
	l := Limits{Timeout: 20 * time.Second}
	for _, c := range []struct {
		bytes int64
		want  time.Duration
	}{
		{0, 20 * time.Second},
		{1 << 20, 40 * time.Second},
		{2 << 20, 60 * time.Second},
		{512 << 10, 30 * time.Second},
	} {
		if got := l.RequestTimeout(c.bytes); got != c.want {
			t.Errorf("%d bytes: %s, want %s", c.bytes, got, c.want)
		}
	}
	if got := (Limits{}).RequestTimeout(0); got != DefaultTimeout {
		t.Errorf("default: %s", got)
	}
	// A small value keeps (almost exactly) the base timeout, so a hang is still caught quickly.
	if got := l.RequestTimeout(4 << 10); got > 20*time.Second+100*time.Millisecond {
		t.Errorf("4 KiB: %s", got)
	}
}

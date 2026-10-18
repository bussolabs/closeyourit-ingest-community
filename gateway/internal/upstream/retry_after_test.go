package upstream

import (
	"testing"
	"time"
)

func TestParseRetryAfterReadsSeconds(t *testing.T) {
	now := time.Date(2026, 7, 12, 6, 0, 0, 0, time.UTC)

	if got := ParseRetryAfter("120", now); got != 2*time.Minute {
		t.Fatalf("delay=%s", got)
	}
}

func TestParseRetryAfterReadsTheHTTPDate(t *testing.T) {
	now := time.Date(2026, 7, 12, 6, 0, 0, 0, time.UTC)

	if got := ParseRetryAfter("Sun, 12 Jul 2026 06:00:30 GMT", now); got != 30*time.Second {
		t.Fatalf("delay=%s", got)
	}
}

func TestParseRetryAfterIgnoresUnusableValues(t *testing.T) {
	now := time.Date(2026, 7, 12, 6, 0, 0, 0, time.UTC)

	for _, value := range []string{"", "  ", "presto", "-5", "0", "Sun, 12 Jul 2026 05:59:00 GMT"} {
		if got := ParseRetryAfter(value, now); got != 0 {
			t.Fatalf("value %q produced delay=%s", value, got)
		}
	}
}

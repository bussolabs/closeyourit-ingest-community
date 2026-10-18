// Package upstream holds the reading of CloseYourIt responses shared between
// direct forwarding and deferred delivery: Retry-After means the same thing on
// both sides, and two copies of the same rule drift apart.
package upstream

import (
	"net/http"
	"strconv"
	"strings"
	"time"
)

// ParseRetryAfter returns the wait requested by the upstream, 0 if the header
// is missing, unreadable or already expired.
func ParseRetryAfter(value string, now time.Time) time.Duration {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0
	}
	if seconds, err := strconv.Atoi(value); err == nil {
		if seconds <= 0 {
			return 0
		}
		return time.Duration(seconds) * time.Second
	}
	when, err := http.ParseTime(value)
	if err != nil || !when.After(now) {
		return 0
	}
	return when.Sub(now)
}

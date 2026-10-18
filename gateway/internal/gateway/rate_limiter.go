package gateway

import (
	"net/http"
	"sync"
	"time"
)

type rateWindow struct {
	startedAt time.Time
	count     int
}

type RateLimiter struct {
	mu       sync.Mutex
	windows  map[string]rateWindow
	limit    int
	interval time.Duration
	now      func() time.Time
	maxKeys  int
	recorder Recorder
}

func NewRateLimiter(limit int, interval time.Duration) *RateLimiter {
	return &RateLimiter{
		windows: make(map[string]rateWindow), limit: limit, interval: interval,
		now: time.Now, maxKeys: 100_000, recorder: nopRecorder{},
	}
}

func (l *RateLimiter) SetRecorder(recorder Recorder) {
	if recorder != nil {
		l.recorder = recorder
	}
}

func (l *RateLimiter) Allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := l.now()
	window, found := l.windows[key]
	if !found && len(l.windows) >= l.maxKeys {
		for existingKey, existingWindow := range l.windows {
			if now.Sub(existingWindow.startedAt) >= l.interval {
				delete(l.windows, existingKey)
			}
		}
		if len(l.windows) >= l.maxKeys {
			return false
		}
	}
	if !found || now.Sub(window.startedAt) >= l.interval {
		l.windows[key] = rateWindow{startedAt: now, count: 1}
		return true
	}
	if window.count >= l.limit {
		return false
	}
	window.count++
	l.windows[key] = window
	return true
}

func (l *RateLimiter) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isControlPath(r.URL.Path) || l.Allow(clientIP(r)) {
			next.ServeHTTP(w, r)
			return
		}
		l.recorder.RecordRejected("rate_limited")
		w.Header().Set("Retry-After", "60")
		writeJSON(w, http.StatusTooManyRequests, map[string]any{"error": map[string]string{
			"code": "R429-INGEST-GATEWAY-001", "message": "Too many requests",
		}})
	})
}

package gateway

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestRateLimiterAppliesBoundaryAndReset(t *testing.T) {
	now := time.Date(2026, 7, 12, 6, 0, 0, 0, time.UTC)
	limiter := NewRateLimiter(2, time.Minute)
	limiter.now = func() time.Time { return now }
	handler := limiter.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))

	for index, expected := range []int{http.StatusNoContent, http.StatusNoContent, http.StatusTooManyRequests} {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodPost, "/api/v1/projects/p/events", nil)
		request.Header.Set("X-Forwarded-For", "203.0.113.1")
		handler.ServeHTTP(recorder, request)
		if recorder.Code != expected {
			t.Fatalf("request %d status=%d, want=%d", index+1, recorder.Code, expected)
		}
	}

	now = now.Add(time.Minute)
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, "/api/v1/projects/p/events", nil)
	request.Header.Set("X-Forwarded-For", "203.0.113.1")
	handler.ServeHTTP(recorder, request)
	if recorder.Code != http.StatusNoContent {
		t.Fatalf("after reset status=%d", recorder.Code)
	}
}

func TestRateLimiterDoesNotBlockHealth(t *testing.T) {
	limiter := NewRateLimiter(0, time.Minute)
	handler := limiter.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	for _, path := range []string{"/up", "/ready", "/version", "/healthz"} {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
		if recorder.Code != http.StatusOK {
			t.Fatalf("%s status=%d", path, recorder.Code)
		}
	}
}

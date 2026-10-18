package gateway

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type recordedUpstream struct {
	source   string
	kind     string
	status   string
	duration time.Duration
}

type recordedReadiness struct {
	directProxyHealthy bool
	queueConnected     bool
	draining           bool
}

type fakeRecorder struct {
	requests   []string
	rejected   []string
	upstream   []recordedUpstream
	publishes  []error
	retryAfter []string
	readiness  []recordedReadiness
}

func (f *fakeRecorder) RecordRequest(kind, outcome string) {
	f.requests = append(f.requests, kind+":"+outcome)
}

func (f *fakeRecorder) RecordRejected(reason string) {
	f.rejected = append(f.rejected, reason)
}

func (f *fakeRecorder) RecordUpstream(source, kind, status string, duration time.Duration) {
	f.upstream = append(f.upstream, recordedUpstream{source: source, kind: kind, status: status, duration: duration})
}

func (f *fakeRecorder) RecordPublish(_ string, _ time.Duration, err error) {
	f.publishes = append(f.publishes, err)
}

func (f *fakeRecorder) RecordRetryAfter(source string, delay time.Duration) {
	f.retryAfter = append(f.retryAfter, fmt.Sprintf("%s:%s", source, delay))
}

func (f *fakeRecorder) SetReadiness(directProxyHealthy, queueConnected, draining bool) {
	f.readiness = append(f.readiness, recordedReadiness{directProxyHealthy, queueConnected, draining})
}

func observedHandler(t *testing.T, client HTTPClient, publisher *fakePublisher) (*Handler, *fakeRecorder) {
	t.Helper()
	handler, _ := newTestHandler(t, client, publisher)
	recorder := &fakeRecorder{}
	handler.SetRecorder(recorder)
	return handler, recorder
}

func postLogs(handler *Handler) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodPost, "https://ingest.example/api/v1/projects/p/logs", strings.NewReader(`[{"m":"x"}]`))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func TestMetricsTellDirectForwardingFromQueueing(t *testing.T) {
	handler, recorder := observedHandler(t, &fakeClient{response: response(http.StatusAccepted, `{}`)}, &fakePublisher{})

	postLogs(handler)

	if len(recorder.requests) != 1 || recorder.requests[0] != "logs:direct" {
		t.Fatalf("recorded requests = %v", recorder.requests)
	}
	if len(recorder.upstream) != 1 || recorder.upstream[0] != (recordedUpstream{source: "direct", kind: "logs", status: "202"}) {
		t.Fatalf("recorded upstream = %+v", recorder.upstream)
	}
	if len(recorder.publishes) != 0 {
		t.Fatalf("publishes recorded without queueing = %v", recorder.publishes)
	}
}

func TestMetricsRecordQueueingAndDegradedUpstreamStatus(t *testing.T) {
	handler, recorder := observedHandler(t, &fakeClient{response: response(http.StatusServiceUnavailable, `{}`)}, &fakePublisher{})

	postLogs(handler)

	if len(recorder.requests) != 1 || recorder.requests[0] != "logs:queued" {
		t.Fatalf("recorded requests = %v", recorder.requests)
	}
	if len(recorder.upstream) != 1 || recorder.upstream[0].status != "503" {
		t.Fatalf("recorded upstream = %+v", recorder.upstream)
	}
	if len(recorder.publishes) != 1 || recorder.publishes[0] != nil {
		t.Fatalf("recorded publishes = %v", recorder.publishes)
	}
}

func TestMetricsTellNetworkFailureFromHTTPCode(t *testing.T) {
	handler, recorder := observedHandler(t, &fakeClient{err: errors.New("connessione rifiutata")}, &fakePublisher{})

	postLogs(handler)

	if len(recorder.upstream) != 1 || recorder.upstream[0].status != "error" {
		t.Fatalf("recorded upstream = %+v", recorder.upstream)
	}
}

func TestMetricsRecordTheLostMessageWhenTheQueueRefuses(t *testing.T) {
	publisher := &fakePublisher{err: errors.New("stream pieno")}
	handler, recorder := observedHandler(t, &fakeClient{response: response(http.StatusServiceUnavailable, `{}`)}, publisher)

	postLogs(handler)

	if len(recorder.requests) != 1 || recorder.requests[0] != "logs:dropped" {
		t.Fatalf("recorded requests = %v", recorder.requests)
	}
	if len(recorder.publishes) != 1 || recorder.publishes[0] == nil {
		t.Fatalf("recorded publishes = %v", recorder.publishes)
	}
}

func TestMetricsObserveTheUpstreamRetryAfter(t *testing.T) {
	upstreamResponse := response(http.StatusTooManyRequests, `{}`)
	upstreamResponse.Header.Set("Retry-After", "120")
	handler, recorder := observedHandler(t, &fakeClient{response: upstreamResponse}, &fakePublisher{})

	postLogs(handler)

	if len(recorder.retryAfter) != 1 || recorder.retryAfter[0] != "direct:2m0s" {
		t.Fatalf("recorded retry-after = %v", recorder.retryAfter)
	}
}

func TestMetricsCountRequestsRejectedAtIngress(t *testing.T) {
	handler, recorder := observedHandler(t, &fakeClient{response: response(http.StatusOK, `{}`)}, &fakePublisher{})

	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "https://ingest.example/api/v1/unknown", strings.NewReader("{}")))
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "https://ingest.example/api/v1/projects/p/logs", nil))
	handler.maxBody = 4
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "https://ingest.example/api/v1/projects/p/logs", strings.NewReader("payload troppo lungo")))

	want := []string{"not_found", "method_not_allowed", "body_too_large"}
	if strings.Join(recorder.rejected, ",") != strings.Join(want, ",") {
		t.Fatalf("recorded rejections = %v", recorder.rejected)
	}
	if len(recorder.requests) != 0 {
		t.Fatalf("a rejected request must not count as accepted: %v", recorder.requests)
	}
}

func TestRateLimiterCountsRejectedRequests(t *testing.T) {
	recorder := &fakeRecorder{}
	limiter := NewRateLimiter(1, time.Minute)
	limiter.SetRecorder(recorder)
	limited := limiter.Middleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))

	for range 2 {
		request := httptest.NewRequest(http.MethodPost, "https://ingest.example/api/v1/projects/p/logs", strings.NewReader("{}"))
		request.RemoteAddr = "203.0.113.7:5000"
		limited.ServeHTTP(httptest.NewRecorder(), request)
	}

	if len(recorder.rejected) != 1 || recorder.rejected[0] != "rate_limited" {
		t.Fatalf("recorded rejections = %v", recorder.rejected)
	}
}

func TestControlEndpointsDoNotPolluteIngressMetrics(t *testing.T) {
	handler, recorder := observedHandler(t, &fakeClient{response: response(http.StatusOK, `{}`)}, &fakePublisher{})

	for _, path := range []string{"/up", "/version", "/healthz"} {
		handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "https://ingest.example"+path, nil))
	}

	if len(recorder.requests) != 0 || len(recorder.rejected) != 0 {
		t.Fatalf("requests=%v rejections=%v", recorder.requests, recorder.rejected)
	}
}

func TestReadinessProbePublishesTheStateOfBothPaths(t *testing.T) {
	handler, recorder := observedHandler(t, &fakeClient{response: response(http.StatusOK, `{}`)}, &fakePublisher{})
	handler.SetQueueConnectedFunc(func() bool { return false })

	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "https://ingest.example/ready", nil))

	if len(recorder.readiness) != 1 {
		t.Fatalf("recorded states = %+v", recorder.readiness)
	}
	if got := recorder.readiness[0]; !got.directProxyHealthy || got.queueConnected || got.draining {
		t.Fatalf("recorded state = %+v", got)
	}
}

func TestHandlerWithoutRecorderDoesNotPanic(t *testing.T) {
	handler, _ := newTestHandler(t, &fakeClient{response: response(http.StatusAccepted, `{}`)}, &fakePublisher{})

	if got := postLogs(handler).Code; got != http.StatusAccepted {
		t.Fatalf("status=%d", got)
	}
	_, _ = io.Copy(io.Discard, strings.NewReader(""))
}

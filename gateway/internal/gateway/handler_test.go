package gateway

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/bussolabs/closeyourit-ingest-community/gateway/internal/cryptor"
	"github.com/bussolabs/closeyourit-ingest-community/gateway/internal/envelope"
	"github.com/bussolabs/closeyourit-ingest-community/gateway/internal/queue"
)

type fakeClient struct {
	response *http.Response
	err      error
	request  *http.Request
}

func (f *fakeClient) Do(request *http.Request) (*http.Response, error) {
	f.request = request
	return f.response, f.err
}

type fakePublisher struct {
	message queue.Message
	err     error
	calls   int
}

func (f *fakePublisher) Publish(_ context.Context, message queue.Message) error {
	f.calls++
	f.message = message
	return f.err
}

func newTestHandler(t *testing.T, client HTTPClient, publisher queue.Publisher) (*Handler, *cryptor.Cryptor) {
	t.Helper()
	key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32))
	c, err := cryptor.New(key)
	if err != nil {
		t.Fatal(err)
	}
	upstream, _ := url.Parse("https://closeyourit.internal")
	handler := NewHandler(upstream, client, publisher, c, slog.New(slog.NewTextHandler(io.Discard, nil)))
	handler.now = func() time.Time { return time.Date(2026, 7, 12, 6, 0, 0, 0, time.UTC) }
	handler.newID = func() (string, error) { return "request-1", nil }
	return handler, c
}

func response(status int, body string) *http.Response {
	headers := make(http.Header)
	headers.Set("Content-Type", "application/json")
	headers.Set(AdmissionHeader, "true")
	return &http.Response{StatusCode: status, Header: headers, Body: io.NopCloser(strings.NewReader(body))}
}

func TestHandlerPropagatesValidResponseWithoutQueueing(t *testing.T) {
	client := &fakeClient{response: response(http.StatusAccepted, `{"data":{"accepted":1}}`)}
	publisher := &fakePublisher{}
	handler, _ := newTestHandler(t, client, publisher)
	req := httptest.NewRequest(http.MethodPost, "https://ingest.example/api/v1/projects/p/logs", strings.NewReader(`[{"message":"ok"}]`))
	req.Header.Set("Authorization", "Bearer token")
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusAccepted || publisher.calls != 0 {
		t.Fatalf("status=%d publish_calls=%d", recorder.Code, publisher.calls)
	}
	if got := client.request.Header.Get("Authorization"); got != "Bearer token" {
		t.Fatalf("forwarded Authorization = %q", got)
	}
}

func TestHandlerPropagatesFourXXWithoutQueueing(t *testing.T) {
	client := &fakeClient{response: response(http.StatusUnauthorized, `{"error":{"code":"R401"}}`)}
	publisher := &fakePublisher{}
	handler, _ := newTestHandler(t, client, publisher)
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "https://ingest.example/api/v1/projects/p/events", strings.NewReader(`{}`)))

	if recorder.Code != http.StatusUnauthorized || publisher.calls != 0 {
		t.Fatalf("status=%d publish_calls=%d", recorder.Code, publisher.calls)
	}
}

func TestHandlerQueuesEncryptedOnFiveXX(t *testing.T) {
	client := &fakeClient{response: response(http.StatusServiceUnavailable, "down")}
	publisher := &fakePublisher{}
	handler, c := newTestHandler(t, client, publisher)
	req := httptest.NewRequest(http.MethodPost, "https://ingest.example/api/v1/projects/p/metrics?source=ruby", strings.NewReader(`{"sample_id":"s1"}`))
	req.Header.Set("Authorization", "Bearer very-secret")
	req.Header.Set("X-Forwarded-For", "203.0.113.8")
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, req)

	if recorder.Code != http.StatusAccepted || recorder.Header().Get("X-CloseYourIt-Queued") != "true" {
		t.Fatalf("status=%d headers=%v", recorder.Code, recorder.Header())
	}
	if publisher.calls != 1 || publisher.message.Kind != "metrics" || publisher.message.ID != "request-1" {
		t.Fatalf("queued message = %#v", publisher.message)
	}
	if bytes.Contains(publisher.message.Ciphertext, []byte("very-secret")) {
		t.Fatal("the bearer appears in the JetStream payload")
	}
	plain, err := c.Decrypt(publisher.message.Ciphertext, []byte("metrics"))
	if err != nil {
		t.Fatal(err)
	}
	stored, err := envelope.Decode(plain)
	if err != nil {
		t.Fatal(err)
	}
	if stored.RawQuery != "source=ruby" || stored.Headers["Authorization"] != "Bearer very-secret" || stored.RemoteAddr != "203.0.113.8" {
		t.Fatalf("stored request = %#v", stored)
	}
}

func TestHandlerRejectsUnauthenticatedNetworkFallback(t *testing.T) {
	client := &fakeClient{err: context.DeadlineExceeded}
	publisher := &fakePublisher{}
	handler, _ := newTestHandler(t, client, publisher)
	recorder := httptest.NewRecorder()

	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "https://ingest.example/api/p/envelope", strings.NewReader("envelope")))

	if recorder.Code != http.StatusServiceUnavailable || publisher.calls != 0 {
		t.Fatalf("status=%d publish_calls=%d", recorder.Code, publisher.calls)
	}
}

func TestHandlerRejectsPathAndBodyOutsideTheContract(t *testing.T) {
	handler, _ := newTestHandler(t, &fakeClient{}, &fakePublisher{})

	unknown := httptest.NewRecorder()
	handler.ServeHTTP(unknown, httptest.NewRequest(http.MethodPost, "https://ingest.example/api/v1/tickets", strings.NewReader(`{}`)))
	if unknown.Code != http.StatusNotFound {
		t.Fatalf("unsupported path status=%d", unknown.Code)
	}

	handler.maxBody = 3
	oversized := httptest.NewRecorder()
	handler.ServeHTTP(oversized, httptest.NewRequest(http.MethodPost, "https://ingest.example/api/v1/projects/p/events", strings.NewReader("1234")))
	if oversized.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("body over limit status=%d", oversized.Code)
	}
}

func readinessOf(t *testing.T, handler *Handler) (int, map[string]any) {
	t.Helper()
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/ready", nil))
	var payload map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("body /ready is not JSON: %s", recorder.Body.String())
	}
	return recorder.Code, payload
}

func assertReadiness(t *testing.T, payload map[string]any, status string, accepting, directProxy, queue bool) {
	t.Helper()
	if payload["status"] != status || payload["accepting"] != accepting {
		t.Fatalf("status/accepting = %v/%v, want %q/%v", payload["status"], payload["accepting"], status, accepting)
	}
	if payload["direct_proxy_healthy"] != directProxy || payload["queue_connected"] != queue {
		t.Fatalf("direct_proxy_healthy/queue_connected = %v/%v, want %v/%v",
			payload["direct_proxy_healthy"], payload["queue_connected"], directProxy, queue)
	}
}

func forwardOnce(t *testing.T, handler *Handler) {
	t.Helper()
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost,
		"https://ingest.example/api/v1/projects/p/events", strings.NewReader(`{}`)))
}

func TestReadyDeclaresBothPathsHealthyBeforeAnyTraffic(t *testing.T) {
	handler, _ := newTestHandler(t, &fakeClient{}, &fakePublisher{})
	handler.SetQueueConnectedFunc(func() bool { return true })

	code, payload := readinessOf(t, handler)

	if code != http.StatusOK {
		t.Fatalf("ready at startup status=%d", code)
	}
	assertReadiness(t, payload, "ready", true, true, true)
}

func TestReadyKeepsAcceptingWithDisconnectedQueue(t *testing.T) {
	handler, _ := newTestHandler(t, &fakeClient{response: response(http.StatusAccepted, `{}`)}, &fakePublisher{})
	handler.SetQueueConnectedFunc(func() bool { return false })
	forwardOnce(t, handler)

	code, payload := readinessOf(t, handler)

	if code != http.StatusOK {
		t.Fatalf("with the queue down the gateway still forwards: status=%d", code)
	}
	assertReadiness(t, payload, "degraded", true, true, false)
}

func TestReadyReportsDegradedDirectProxyAfterNetworkError(t *testing.T) {
	handler, _ := newTestHandler(t, &fakeClient{err: context.DeadlineExceeded}, &fakePublisher{})
	handler.SetQueueConnectedFunc(func() bool { return true })
	forwardOnce(t, handler)

	code, payload := readinessOf(t, handler)

	if code != http.StatusServiceUnavailable {
		t.Fatalf("authorization unavailable: status=%d", code)
	}
	assertReadiness(t, payload, "unavailable", false, false, true)
}

func TestReadyReportsDegradedDirectProxyOnQueueableResponse(t *testing.T) {
	handler, _ := newTestHandler(t, &fakeClient{response: response(http.StatusServiceUnavailable, "down")}, &fakePublisher{})
	handler.SetQueueConnectedFunc(func() bool { return true })
	forwardOnce(t, handler)

	_, payload := readinessOf(t, handler)

	assertReadiness(t, payload, "unavailable", false, false, true)
}

func TestDirectProxyBecomesHealthyAfterASuccessfulForward(t *testing.T) {
	client := &fakeClient{err: context.DeadlineExceeded}
	handler, _ := newTestHandler(t, client, &fakePublisher{})
	handler.SetQueueConnectedFunc(func() bool { return true })
	forwardOnce(t, handler)
	if _, payload := readinessOf(t, handler); payload["direct_proxy_healthy"] != false {
		t.Fatalf("direct proxy not marked degraded: %v", payload)
	}

	client.err = nil
	client.response = response(http.StatusAccepted, `{}`)
	forwardOnce(t, handler)

	_, payload := readinessOf(t, handler)
	assertReadiness(t, payload, "ready", true, true, true)
}

func TestReadyDoesNotAcceptWhenQueueAndDirectProxyAreBothDown(t *testing.T) {
	handler, _ := newTestHandler(t, &fakeClient{err: context.DeadlineExceeded}, &fakePublisher{err: errors.New("nats down")})
	handler.SetQueueConnectedFunc(func() bool { return false })
	forwardOnce(t, handler)

	code, payload := readinessOf(t, handler)

	if code != http.StatusServiceUnavailable {
		t.Fatalf("without available paths status=%d", code)
	}
	assertReadiness(t, payload, "unavailable", false, false, false)
}

func TestUpStaysPositiveWithAllDependenciesDown(t *testing.T) {
	handler, _ := newTestHandler(t, &fakeClient{err: context.DeadlineExceeded}, &fakePublisher{err: errors.New("nats down")})
	handler.SetQueueConnectedFunc(func() bool { return false })
	forwardOnce(t, handler)

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/up", nil))

	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"status":"ok"`) {
		t.Fatalf("liveness status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestShutdownAnnouncesDrainingWithoutTurningOffLiveness(t *testing.T) {
	handler, _ := newTestHandler(t, &fakeClient{response: response(http.StatusAccepted, `{}`)}, &fakePublisher{})
	handler.SetQueueConnectedFunc(func() bool { return true })

	handler.BeginShutdown()

	code, payload := readinessOf(t, handler)
	if code != http.StatusServiceUnavailable {
		t.Fatalf("during shutdown status=%d", code)
	}
	assertReadiness(t, payload, "draining", false, true, true)

	live := httptest.NewRecorder()
	handler.ServeHTTP(live, httptest.NewRequest(http.MethodGet, "/up", nil))
	if live.Code != http.StatusOK {
		t.Fatalf("liveness must not drop during draining: status=%d", live.Code)
	}
}

func TestHealthzKeepsTheLegacyQueueGate(t *testing.T) {
	handler, _ := newTestHandler(t, &fakeClient{}, &fakePublisher{})

	handler.SetQueueConnectedFunc(func() bool { return true })
	connected := httptest.NewRecorder()
	handler.ServeHTTP(connected, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if connected.Code != http.StatusOK {
		t.Fatalf("healthz with connected queue status=%d", connected.Code)
	}

	handler.SetQueueConnectedFunc(func() bool { return false })
	disconnected := httptest.NewRecorder()
	handler.ServeHTTP(disconnected, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if disconnected.Code != http.StatusServiceUnavailable {
		t.Fatalf("healthz with disconnected queue status=%d", disconnected.Code)
	}
}

func TestVersionExposesTheBuildIdentity(t *testing.T) {
	handler, _ := newTestHandler(t, &fakeClient{}, &fakePublisher{})

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/version", nil))

	if recorder.Code != http.StatusOK {
		t.Fatalf("version status=%d", recorder.Code)
	}
	var payload map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("body /version is not JSON: %s", recorder.Body.String())
	}
	for _, field := range []string{"app", "tag", "sha", "short_sha", "build_time", "environment", "go_version"} {
		if _, present := payload[field]; !present {
			t.Fatalf("field %q missing from /version: %v", field, payload)
		}
	}
	if payload["app"] != "closeyourit-ingest" {
		t.Fatalf("app = %v", payload["app"])
	}
}

func TestClientCancellationDoesNotMarkTheUpstreamDegraded(t *testing.T) {
	handler, _ := newTestHandler(t, &fakeClient{err: context.Canceled}, &fakePublisher{})
	handler.SetQueueConnectedFunc(func() bool { return true })

	abandoned, cancel := context.WithCancel(context.Background())
	cancel()
	request := httptest.NewRequest(http.MethodPost, "https://ingest.example/api/v1/projects/p/events",
		strings.NewReader(`{}`)).WithContext(abandoned)
	handler.ServeHTTP(httptest.NewRecorder(), request)

	_, payload := readinessOf(t, handler)

	assertReadiness(t, payload, "ready", true, true, true)
}

func TestNegativeUpstreamObservationExpiresByItself(t *testing.T) {
	handler, _ := newTestHandler(t, &fakeClient{err: context.DeadlineExceeded}, &fakePublisher{})
	handler.SetQueueConnectedFunc(func() bool { return false })
	current := time.Date(2026, 7, 12, 6, 0, 0, 0, time.UTC)
	handler.now = func() time.Time { return current }
	forwardOnce(t, handler)

	code, payload := readinessOf(t, handler)
	if code != http.StatusServiceUnavailable {
		t.Fatalf("right after the failure status=%d", code)
	}
	assertReadiness(t, payload, "unavailable", false, false, false)

	// Without traffic the gateway cannot retry: after the window it goes back
	// to optimistic, otherwise it would stay out of the pool forever.
	current = current.Add(directProxyFailureTTL + time.Second)

	code, payload = readinessOf(t, handler)
	if code != http.StatusOK {
		t.Fatalf("after expiry status=%d", code)
	}
	assertReadiness(t, payload, "degraded", true, true, false)
}

func TestNegativeObservationHoldsWithinTheWindow(t *testing.T) {
	handler, _ := newTestHandler(t, &fakeClient{err: context.DeadlineExceeded}, &fakePublisher{})
	handler.SetQueueConnectedFunc(func() bool { return true })
	current := time.Date(2026, 7, 12, 6, 0, 0, 0, time.UTC)
	handler.now = func() time.Time { return current }
	forwardOnce(t, handler)

	current = current.Add(directProxyFailureTTL - time.Second)

	_, payload := readinessOf(t, handler)
	assertReadiness(t, payload, "unavailable", false, false, true)
}

func TestHandlerRejectsNonGetMethodOnControlEndpoints(t *testing.T) {
	handler, _ := newTestHandler(t, &fakeClient{}, &fakePublisher{})
	for _, path := range []string{"/up", "/ready", "/version", "/healthz"} {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, path, nil))
		if recorder.Code != http.StatusMethodNotAllowed {
			t.Fatalf("%s status=%d", path, recorder.Code)
		}
	}
}

package gateway

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/bussolabs/closeyourit-ingest-community/gateway/internal/cryptor"
	"github.com/bussolabs/closeyourit-ingest-community/gateway/internal/envelope"
)

const traceparentDiProva = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"

func postWithTrace(t *testing.T, handler *Handler, headers map[string]string) {
	t.Helper()
	request := httptest.NewRequest(http.MethodPost, "https://ingest.example/api/v1/projects/p/events", strings.NewReader(`{}`))
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	handler.ServeHTTP(httptest.NewRecorder(), request)
}

func queuedEnvelope(t *testing.T, c *cryptor.Cryptor, publisher *fakePublisher) envelope.Request {
	t.Helper()
	if publisher.calls != 1 {
		t.Fatalf("publish_calls=%d", publisher.calls)
	}
	plain, err := c.Decrypt(publisher.message.Ciphertext, []byte(publisher.message.Kind))
	if err != nil {
		t.Fatal(err)
	}
	stored, err := envelope.Decode(plain)
	if err != nil {
		t.Fatal(err)
	}
	return stored
}

func TestDirectForwardingPropagatesTheW3CContext(t *testing.T) {
	client := &fakeClient{response: response(http.StatusAccepted, `{}`)}
	handler, _ := newTestHandler(t, client, &fakePublisher{})

	postWithTrace(t, handler, map[string]string{
		"traceparent": traceparentDiProva,
		"tracestate":  "rojo=00f067aa0ba902b7,congo=t61rcWkgMzE",
	})

	if got := client.request.Header.Get("Traceparent"); got != traceparentDiProva {
		t.Fatalf("forwarded traceparent = %q", got)
	}
	if got := client.request.Header.Get("Tracestate"); got != "rojo=00f067aa0ba902b7,congo=t61rcWkgMzE" {
		t.Fatalf("forwarded tracestate = %q", got)
	}
}

func TestQueuedDeliveryKeepsTheW3CContextInTheEnvelope(t *testing.T) {
	publisher := &fakePublisher{}
	handler, c := newTestHandler(t, &fakeClient{response: response(http.StatusServiceUnavailable, "down")}, publisher)

	postWithTrace(t, handler, map[string]string{
		"traceparent": traceparentDiProva,
		"tracestate":  "rojo=1",
		"baggage":     "userId=42",
	})

	stored := queuedEnvelope(t, c, publisher)
	if stored.Headers["Traceparent"] != traceparentDiProva || stored.Headers["Tracestate"] != "rojo=1" {
		t.Fatalf("envelope = %v", stored.Headers)
	}
	if stored.Headers["Baggage"] != "userId=42" {
		t.Fatalf("stored baggage = %q", stored.Headers["Baggage"])
	}
}

func TestMalformedContextReachesNeitherUpstreamNorQueue(t *testing.T) {
	publisher := &fakePublisher{}
	client := &fakeClient{response: response(http.StatusServiceUnavailable, "down")}
	handler, c := newTestHandler(t, client, publisher)

	postWithTrace(t, handler, map[string]string{
		"traceparent": "00-non-esadecimale-01",
		"tracestate":  "rojo=1",
	})

	if got := client.request.Header.Get("Traceparent"); got != "" {
		t.Fatalf("malformed traceparent forwarded = %q", got)
	}
	if got := client.request.Header.Get("Tracestate"); got != "" {
		t.Fatalf("tracestate without trace forwarded = %q", got)
	}
	stored := queuedEnvelope(t, c, publisher)
	if _, present := stored.Headers["Traceparent"]; present {
		t.Fatalf("envelope = %v", stored.Headers)
	}
	if _, present := stored.Headers["Tracestate"]; present {
		t.Fatalf("envelope = %v", stored.Headers)
	}
}

// The specification writes the names in lowercase, SDKs send them however they
// happen to, and on HTTP case does not matter. The test starts from a real client
// because it is the only way to get a non-canonical name to the gateway truly on the wire.
func TestContextIsRecognizedWhateverTheNameCase(t *testing.T) {
	client := &fakeClient{response: response(http.StatusAccepted, `{}`)}
	handler, _ := newTestHandler(t, client, &fakePublisher{})
	gateway := httptest.NewServer(handler)
	defer gateway.Close()

	request, err := http.NewRequest(http.MethodPost, gateway.URL+"/api/v1/projects/p/events", strings.NewReader(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	request.Header["TRACEPARENT"] = []string{traceparentDiProva}
	request.Header["tracestate"] = []string{"rojo=1"}
	request.Header["BaGgAgE"] = []string{"userId=42"}
	reply, err := gateway.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer reply.Body.Close()

	if got := client.request.Header.Get("traceparent"); got != traceparentDiProva {
		t.Fatalf("forwarded traceparent = %q", got)
	}
	if got := client.request.Header.Get("tracestate"); got != "rojo=1" {
		t.Fatalf("forwarded tracestate = %q", got)
	}
	if got := client.request.Header.Get("baggage"); got != "userId=42" {
		t.Fatalf("forwarded baggage = %q", got)
	}
}

func TestSensitiveBaggageDoesNotCrossTheGateway(t *testing.T) {
	client := &fakeClient{response: response(http.StatusAccepted, `{}`)}
	handler, _ := newTestHandler(t, client, &fakePublisher{})

	postWithTrace(t, handler, map[string]string{
		"traceparent": traceparentDiProva,
		"baggage":     "userId=42,session_token=abc123",
	})

	got := client.request.Header.Get("Baggage")
	if strings.Contains(got, "abc123") {
		t.Fatalf("the sensitive baggage passed = %q", got)
	}
	if got != "userId=42" {
		t.Fatalf("forwarded baggage = %q", got)
	}
}

func TestBaggageBeyondTheCapIsTrimmedBeforeForwarding(t *testing.T) {
	client := &fakeClient{response: response(http.StatusAccepted, `{}`)}
	handler, _ := newTestHandler(t, client, &fakePublisher{})
	oversized := make([]string, 0, 12)
	for i := range 12 {
		oversized = append(oversized, "k"+string(rune('a'+i))+"="+strings.Repeat("x", 1000))
	}

	postWithTrace(t, handler, map[string]string{
		"traceparent": traceparentDiProva,
		"baggage":     strings.Join(oversized, ","),
	})

	got := client.request.Header.Get("Baggage")
	if len(got) > 8192 {
		t.Fatalf("forwarded baggage %d bytes long", len(got))
	}
	if !strings.HasPrefix(got, oversized[0]) {
		t.Fatalf("forwarded baggage = %.40q", got)
	}
}

// The fake client does not go through a real HTTP stack: here the context passes
// through a real upstream, which is the only place where you find out whether the
// value survives being written on the wire.
func TestContextReachesARealUpstream(t *testing.T) {
	received := make(chan http.Header, 1)
	upstreamServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received <- r.Header.Clone()
		w.WriteHeader(http.StatusAccepted)
	}))
	defer upstreamServer.Close()

	target, err := url.Parse(upstreamServer.URL)
	if err != nil {
		t.Fatal(err)
	}
	handler, _ := newTestHandler(t, upstreamServer.Client(), &fakePublisher{})
	handler.upstream = target

	postWithTrace(t, handler, map[string]string{
		"traceparent": traceparentDiProva,
		"tracestate":  "rojo=1",
		"baggage":     "userId=42,api_key=segreto",
	})

	headers := <-received
	if headers.Get("Traceparent") != traceparentDiProva || headers.Get("Tracestate") != "rojo=1" {
		t.Fatalf("real upstream received %v", headers)
	}
	if headers.Get("Baggage") != "userId=42" {
		t.Fatalf("received baggage = %q", headers.Get("Baggage"))
	}
}

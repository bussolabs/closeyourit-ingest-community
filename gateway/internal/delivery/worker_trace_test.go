package delivery

import (
	"context"
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

const traceparentDiProva = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"

func deliveryWithHeaders(t *testing.T, c *cryptor.Cryptor, headers map[string]string) *queue.Delivery {
	t.Helper()
	plain, err := envelope.Encode(envelope.Request{
		Method: http.MethodPost, Path: "/api/v1/projects/p/logs", Headers: headers,
		RemoteAddr: "203.0.113.5", ReceivedAt: time.Date(2026, 7, 12, 5, 0, 0, 0, time.UTC),
		Body: []byte(`{"message":"ok"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := c.Encrypt(plain, []byte("logs"))
	if err != nil {
		t.Fatal(err)
	}
	message := &queue.Delivery{ID: "r1", Kind: "logs", Ciphertext: ciphertext, Attempts: 1}
	message.Ack = func(context.Context) error { return nil }
	message.Retry = func(time.Duration) error { t.Fatal("unexpected retry"); return nil }
	return message
}

// deliverTo carries an envelope all the way to a real upstream and returns the
// headers that it saw arrive.
func deliverTo(t *testing.T, headers map[string]string) http.Header {
	t.Helper()
	received := make(chan http.Header, 1)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received <- r.Header.Clone()
		w.WriteHeader(http.StatusAccepted)
	}))
	defer backend.Close()

	target, err := url.Parse(backend.URL)
	if err != nil {
		t.Fatal(err)
	}
	w, c := testWorker(t, backend.Client(), &fakeDeadLetters{})
	w.upstream = target

	w.process(context.Background(), deliveryWithHeaders(t, c, headers))

	return <-received
}

func TestQueuedDeliveryPropagatesTheW3CContext(t *testing.T) {
	got := deliverTo(t, map[string]string{
		"Traceparent": traceparentDiProva,
		"Tracestate":  "rojo=1",
		"Baggage":     "userId=42",
	})

	if got.Get("Traceparent") != traceparentDiProva || got.Get("Tracestate") != "rojo=1" {
		t.Fatalf("upstream received %v", got)
	}
	if got.Get("Baggage") != "userId=42" {
		t.Fatalf("received baggage = %q", got.Get("Baggage"))
	}
}

// Messages written by a gateway that predates the allowlist stay in the queue for
// days: applying the policy only at ingress would deliver them intact.
func TestQueuedDeliveryCleansANonConformingEnvelope(t *testing.T) {
	got := deliverTo(t, map[string]string{
		"Traceparent": "00-non-esadecimale-01",
		"Tracestate":  "rojo=1",
		"Baggage":     "userId=42,session_token=abc123",
	})

	if got.Get("Traceparent") != "" || got.Get("Tracestate") != "" {
		t.Fatalf("non-conforming context delivered: %v", got)
	}
	if strings.Contains(got.Get("Baggage"), "abc123") {
		t.Fatalf("sensitive baggage delivered = %q", got.Get("Baggage"))
	}
	if got.Get("Baggage") != "userId=42" {
		t.Fatalf("delivered baggage = %q", got.Get("Baggage"))
	}
}

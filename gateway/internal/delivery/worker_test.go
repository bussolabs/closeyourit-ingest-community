package delivery

import (
	"bytes"
	"context"
	"encoding/base64"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/bussolabs/closeyourit-ingest-community/gateway/internal/cryptor"
	"github.com/bussolabs/closeyourit-ingest-community/gateway/internal/envelope"
	"github.com/bussolabs/closeyourit-ingest-community/gateway/internal/queue"
)

type fakeConsumer struct{}

func (fakeConsumer) Next(context.Context) (*queue.Delivery, error) { return nil, queue.ErrNoMessage }

type fakeDeadLetters struct {
	calls   int
	reason  string
	message queue.Message
	err     error
}

func (f *fakeDeadLetters) DeadLetter(_ context.Context, message queue.Message, reason string) error {
	f.calls++
	f.message = message
	f.reason = reason
	return f.err
}

type fakeHTTPClient struct {
	response *http.Response
	err      error
	request  *http.Request
}

func (f *fakeHTTPClient) Do(request *http.Request) (*http.Response, error) {
	f.request = request
	return f.response, f.err
}

func testWorker(t *testing.T, client HTTPClient, deadLetters queue.DeadLetterPublisher) (*Worker, *cryptor.Cryptor) {
	t.Helper()
	key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{3}, 32))
	c, err := cryptor.New(key)
	if err != nil {
		t.Fatal(err)
	}
	upstream, _ := url.Parse("https://closeyourit.internal")
	w := NewWorker(fakeConsumer{}, deadLetters, c, upstream, client, slog.New(slog.NewTextHandler(io.Discard, nil)))
	w.now = func() time.Time { return time.Date(2026, 7, 12, 6, 0, 0, 0, time.UTC) }
	return w, c
}

func encryptedDelivery(t *testing.T, c *cryptor.Cryptor, kind string, attempts uint64) *queue.Delivery {
	t.Helper()
	plain, err := envelope.Encode(envelope.Request{
		Method: http.MethodPost, Path: "/api/v1/projects/p/logs", Headers: map[string]string{"Authorization": "Bearer token"},
		RemoteAddr: "203.0.113.5", ReceivedAt: time.Date(2026, 7, 12, 5, 0, 0, 0, time.UTC), Body: []byte(`{"message":"ok"}`),
	})
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := c.Encrypt(plain, []byte(kind))
	if err != nil {
		t.Fatal(err)
	}
	return &queue.Delivery{ID: "r1", Kind: kind, Ciphertext: ciphertext, Attempts: attempts}
}

func TestProcessAcksOnSuccessfulDelivery(t *testing.T) {
	client := &fakeHTTPClient{response: &http.Response{StatusCode: http.StatusAccepted, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("ok"))}}
	dlq := &fakeDeadLetters{}
	w, c := testWorker(t, client, dlq)
	acked := 0
	message := encryptedDelivery(t, c, "logs", 1)
	message.Ack = func(context.Context) error { acked++; return nil }
	message.Retry = func(time.Duration) error { t.Fatal("unexpected retry"); return nil }

	w.process(context.Background(), message)

	if acked != 1 || dlq.calls != 0 {
		t.Fatalf("ack=%d dlq=%d", acked, dlq.calls)
	}
	if client.request.Header.Get("Authorization") != "Bearer token" || client.request.Header.Get("X-Forwarded-For") != "203.0.113.5" {
		t.Fatalf("header delivery=%v", client.request.Header)
	}
}

func TestProcessRetriesFiveXXWithBackoff(t *testing.T) {
	client := &fakeHTTPClient{response: &http.Response{StatusCode: http.StatusServiceUnavailable, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("down"))}}
	w, c := testWorker(t, client, &fakeDeadLetters{})
	message := encryptedDelivery(t, c, "logs", 2)
	var retried time.Duration
	message.Ack = func(context.Context) error { t.Fatal("unexpected ack"); return nil }
	message.Retry = func(delay time.Duration) error { retried = delay; return nil }

	w.process(context.Background(), message)

	if retried != 30*time.Second {
		t.Fatalf("retry delay=%s", retried)
	}
}

func TestProcessIsolatesPermanentFourXX(t *testing.T) {
	client := &fakeHTTPClient{response: &http.Response{StatusCode: http.StatusUnauthorized, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("unauthorized"))}}
	dlq := &fakeDeadLetters{}
	w, c := testWorker(t, client, dlq)
	acked := 0
	message := encryptedDelivery(t, c, "logs", 1)
	message.Ack = func(context.Context) error { acked++; return nil }
	message.Retry = func(time.Duration) error { t.Fatal("unexpected retry"); return nil }

	w.process(context.Background(), message)

	if dlq.calls != 1 || dlq.reason != "http_401" || acked != 1 {
		t.Fatalf("dlq=%d reason=%q ack=%d", dlq.calls, dlq.reason, acked)
	}
}

func TestProcessIsolatesAfterTheLastAttempt(t *testing.T) {
	client := &fakeHTTPClient{err: context.DeadlineExceeded}
	dlq := &fakeDeadLetters{}
	w, c := testWorker(t, client, dlq)
	acked := 0
	message := encryptedDelivery(t, c, "logs", DefaultMaxAttempts)
	message.Ack = func(context.Context) error { acked++; return nil }
	message.Retry = func(time.Duration) error { t.Fatal("unexpected retry"); return nil }

	w.process(context.Background(), message)

	if dlq.reason != "network_error_max_attempts" || acked != 1 {
		t.Fatalf("reason=%q ack=%d", dlq.reason, acked)
	}
}

func TestRetryDelayCoversBoundariesAndRetryAfter(t *testing.T) {
	now := time.Date(2026, 7, 12, 6, 0, 0, 0, time.UTC)
	cases := []struct {
		attempt uint64
		header  string
		want    time.Duration
	}{
		{0, "", 5 * time.Second}, {1, "", 5 * time.Second}, {2, "", 30 * time.Second},
		{99, "", time.Hour}, {3, "17", 17 * time.Second},
		{3, now.Add(90 * time.Second).Format(http.TimeFormat), 90 * time.Second},
		{3, "7200", time.Hour},
	}
	for _, tc := range cases {
		if got := RetryDelay(tc.attempt, tc.header, now); got != tc.want {
			t.Fatalf("attempt=%d header=%q got=%s want=%s", tc.attempt, tc.header, got, tc.want)
		}
	}
}

func TestSetMaxAttemptsBringsTheDeadLetterForwardAndIgnoresInvalidValues(t *testing.T) {
	client := &fakeHTTPClient{err: context.DeadlineExceeded}
	dlq := &fakeDeadLetters{}
	w, c := testWorker(t, client, dlq)
	w.SetMaxAttempts(0)
	if w.maxAttempts != DefaultMaxAttempts {
		t.Fatalf("max_attempts=%d after an invalid value", w.maxAttempts)
	}

	w.SetMaxAttempts(3)
	message := encryptedDelivery(t, c, "logs", 3)
	acked := 0
	message.Ack = func(context.Context) error { acked++; return nil }
	message.Retry = func(time.Duration) error { t.Fatal("unexpected retry"); return nil }

	w.process(context.Background(), message)

	if dlq.reason != "network_error_max_attempts" || acked != 1 {
		t.Fatalf("reason=%q ack=%d", dlq.reason, acked)
	}
}

func TestProcessDuringShutdownRequeuesWithoutConsumingTheAttempt(t *testing.T) {
	client := &fakeHTTPClient{err: context.Canceled}
	dlq := &fakeDeadLetters{}
	w, c, recorder := observedWorker(t, client, dlq)
	// Last available attempt: if shutdown counted as an upstream
	// failure, this message would end up isolated through no fault of its own.
	message := encryptedDelivery(t, c, "logs", DefaultMaxAttempts)
	retried := time.Duration(-1)
	message.Ack = func(context.Context) error { t.Fatal("unexpected ack"); return nil }
	message.Retry = func(delay time.Duration) error { retried = delay; return nil }
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	w.process(ctx, message)

	if dlq.calls != 0 {
		t.Fatalf("dead letter=%d during shutdown", dlq.calls)
	}
	if retried != 0 {
		t.Fatalf("retry delay=%s: the message does not become available again right away", retried)
	}
	if len(recorder.upstream) != 0 || len(recorder.failures) != 0 {
		t.Fatalf("upstream=%v failures=%v: shutdown is counted as a failure", recorder.upstream, recorder.failures)
	}
}

func TestOTLPRetryTableDoesNotChangeNativeDelivery(t *testing.T) {
	for _, code := range []int{408, 425, 429, 500, 501, 502, 503, 504, 505} {
		want := code == 429 || code == 502 || code == 503 || code == 504
		if got := retryableDelivery("otlp_traces", code); got != want {
			t.Errorf("OTLP status=%d retry=%v want=%v", code, got, want)
		}
		if !retryableDelivery("events", code) {
			t.Errorf("Native status=%d must retain its retry behavior", code)
		}
	}
}

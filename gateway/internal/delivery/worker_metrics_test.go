package delivery

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bussolabs/closeyourit-ingest-community/gateway/internal/cryptor"
	"github.com/bussolabs/closeyourit-ingest-community/gateway/internal/envelope"
	"github.com/bussolabs/closeyourit-ingest-community/gateway/internal/queue"
)

type fakeRecorder struct {
	mu         sync.Mutex
	upstream   []string
	deliveries []string
	failures   []string
	retryAfter []string
	workers    int
	busy       int
	maxBusy    int
}

func (f *fakeRecorder) RecordUpstream(source, kind, status string, _ time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.upstream = append(f.upstream, source+":"+kind+":"+status)
}

func (f *fakeRecorder) RecordRetryAfter(source string, delay time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.retryAfter = append(f.retryAfter, source+":"+delay.String())
}

func (f *fakeRecorder) RecordDelivery(kind, outcome string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.deliveries = append(f.deliveries, kind+":"+outcome)
}

func (f *fakeRecorder) RecordDeliveryFailure(reason string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failures = append(f.failures, reason)
}

func (f *fakeRecorder) SetDeliveryWorkers(total int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.workers = total
}

func (f *fakeRecorder) AddBusyDeliveryWorkers(delta int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.busy += delta
	if f.busy > f.maxBusy {
		f.maxBusy = f.busy
	}
}

func observedWorker(t *testing.T, client HTTPClient, deadLetters queue.DeadLetterPublisher) (*Worker, *cryptor.Cryptor, *fakeRecorder) {
	t.Helper()
	worker, c := testWorker(t, client, deadLetters)
	recorder := &fakeRecorder{}
	worker.SetRecorder(recorder)
	return worker, c, recorder
}

func queuedMessage(t *testing.T, c *cryptor.Cryptor, attempts uint64) *queue.Delivery {
	t.Helper()
	plain, err := envelope.Encode(envelope.Request{
		Method: http.MethodPost, Path: "/api/v1/projects/p/events",
		Headers: map[string]string{}, ReceivedAt: time.Now().UTC(), Body: []byte(`[{"m":"x"}]`),
	})
	if err != nil {
		t.Fatal(err)
	}
	ciphertext, err := c.Encrypt(plain, []byte("events"))
	if err != nil {
		t.Fatal(err)
	}
	return &queue.Delivery{
		ID: "request-1", Kind: "events", Ciphertext: ciphertext, Attempts: attempts,
		Ack:   func(context.Context) error { return nil },
		Retry: func(time.Duration) error { return nil },
	}
}

func deliveryResponse(status int, header http.Header) *http.Response {
	if header == nil {
		header = http.Header{}
	}
	return &http.Response{StatusCode: status, Header: header, Body: io.NopCloser(strings.NewReader("{}"))}
}

func TestMetricsRecordTheSuccessfulDelivery(t *testing.T) {
	worker, c, recorder := observedWorker(t, &fakeHTTPClient{response: deliveryResponse(http.StatusOK, nil)}, &fakeDeadLetters{})

	worker.process(context.Background(), queuedMessage(t, c, 1))

	if strings.Join(recorder.deliveries, ",") != "events:delivered" {
		t.Fatalf("recorded outcomes = %v", recorder.deliveries)
	}
	if strings.Join(recorder.upstream, ",") != "delivery:events:200" {
		t.Fatalf("recorded upstream = %v", recorder.upstream)
	}
	if len(recorder.failures) != 0 {
		t.Fatalf("failure reasons on a successful delivery = %v", recorder.failures)
	}
}

func TestMetricsSeparateNetworkFailureFromAnUpstreamCode(t *testing.T) {
	worker, c, recorder := observedWorker(t, &fakeHTTPClient{err: errors.New("connessione rifiutata")}, &fakeDeadLetters{})

	worker.process(context.Background(), queuedMessage(t, c, 1))

	if strings.Join(recorder.upstream, ",") != "delivery:events:error" {
		t.Fatalf("recorded upstream = %v", recorder.upstream)
	}
	if strings.Join(recorder.deliveries, ",") != "events:retried" {
		t.Fatalf("recorded outcomes = %v", recorder.deliveries)
	}
	if strings.Join(recorder.failures, ",") != "network_error" {
		t.Fatalf("recorded reasons = %v", recorder.failures)
	}
}

func TestMetricsObserveTheRetryAfterDuringDelivery(t *testing.T) {
	header := http.Header{"Retry-After": []string{"300"}}
	worker, c, recorder := observedWorker(t, &fakeHTTPClient{response: deliveryResponse(http.StatusTooManyRequests, header)}, &fakeDeadLetters{})

	worker.process(context.Background(), queuedMessage(t, c, 1))

	if strings.Join(recorder.retryAfter, ",") != "delivery:5m0s" {
		t.Fatalf("recorded retry-after = %v", recorder.retryAfter)
	}
	if strings.Join(recorder.failures, ",") != "http_429" {
		t.Fatalf("recorded reasons = %v", recorder.failures)
	}
}

func TestMetricsRecordTheDeadLetterWithItsReason(t *testing.T) {
	worker, c, recorder := observedWorker(t, &fakeHTTPClient{response: deliveryResponse(http.StatusBadRequest, nil)}, &fakeDeadLetters{})

	worker.process(context.Background(), queuedMessage(t, c, 1))

	if strings.Join(recorder.deliveries, ",") != "events:dead_lettered" {
		t.Fatalf("recorded outcomes = %v", recorder.deliveries)
	}
	if strings.Join(recorder.failures, ",") != "http_400" {
		t.Fatalf("recorded reasons = %v", recorder.failures)
	}
}

func TestMetricsCountTheDeadLetterOnceForExhaustedAttempts(t *testing.T) {
	worker, c, recorder := observedWorker(t, &fakeHTTPClient{response: deliveryResponse(http.StatusServiceUnavailable, nil)}, &fakeDeadLetters{})

	worker.process(context.Background(), queuedMessage(t, c, DefaultMaxAttempts))

	if strings.Join(recorder.deliveries, ",") != "events:dead_lettered" {
		t.Fatalf("recorded outcomes = %v", recorder.deliveries)
	}
	if strings.Join(recorder.failures, ",") != "http_503_max_attempts" {
		t.Fatalf("recorded reasons = %v", recorder.failures)
	}
}

func TestMetricsRecordTheUnreadableMessage(t *testing.T) {
	worker, _, recorder := observedWorker(t, &fakeHTTPClient{response: deliveryResponse(http.StatusOK, nil)}, &fakeDeadLetters{})
	message := &queue.Delivery{
		ID: "request-1", Kind: "events", Ciphertext: []byte("non decifrabile"), Attempts: 1,
		Ack:   func(context.Context) error { return nil },
		Retry: func(time.Duration) error { return nil },
	}

	worker.process(context.Background(), message)

	if strings.Join(recorder.deliveries, ",") != "events:dead_lettered" {
		t.Fatalf("recorded outcomes = %v", recorder.deliveries)
	}
	if strings.Join(recorder.failures, ",") != "decrypt_failed" {
		t.Fatalf("recorded reasons = %v", recorder.failures)
	}
	if len(recorder.upstream) != 0 {
		t.Fatalf("a message never sent must not appear among the upstream responses: %v", recorder.upstream)
	}
}

func TestWorkerSaturationStaysWithinTheConfiguredConcurrency(t *testing.T) {
	worker, _, recorder := observedWorker(t, &fakeHTTPClient{response: deliveryResponse(http.StatusOK, nil)}, &fakeDeadLetters{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	go func() { _ = worker.Run(ctx, 3) }()
	deadline := time.After(2 * time.Second)
	for {
		recorder.mu.Lock()
		configured := recorder.workers
		recorder.mu.Unlock()
		if configured == 3 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("the configured workers were not published")
		case <-time.After(5 * time.Millisecond):
		}
	}

	cancel()
	recorder.mu.Lock()
	defer recorder.mu.Unlock()
	if recorder.busy != 0 || recorder.maxBusy > 3 {
		t.Fatalf("busy=%d max_busy=%d", recorder.busy, recorder.maxBusy)
	}
}

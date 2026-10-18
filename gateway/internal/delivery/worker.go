package delivery

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/bussolabs/closeyourit-ingest-community/gateway/internal/cryptor"
	"github.com/bussolabs/closeyourit-ingest-community/gateway/internal/envelope"
	"github.com/bussolabs/closeyourit-ingest-community/gateway/internal/queue"
	"github.com/bussolabs/closeyourit-ingest-community/gateway/internal/tracecontext"
	"github.com/bussolabs/closeyourit-ingest-community/gateway/internal/upstream"
)

const DefaultMaxAttempts uint64 = 20

type HTTPClient interface {
	Do(*http.Request) (*http.Response, error)
}

// Recorder receives the operational facts of deferred delivery. As in ingress
// the worker states the outcome and not the format: without an observer it passes the no-op.
type Recorder interface {
	RecordUpstream(source, kind, status string, duration time.Duration)
	RecordRetryAfter(source string, delay time.Duration)
	RecordDelivery(kind, outcome string)
	RecordDeliveryFailure(reason string)
	SetDeliveryWorkers(total int)
	AddBusyDeliveryWorkers(delta int)
}

type nopRecorder struct{}

func (nopRecorder) RecordUpstream(string, string, string, time.Duration) {}
func (nopRecorder) RecordRetryAfter(string, time.Duration)               {}
func (nopRecorder) RecordDelivery(string, string)                        {}
func (nopRecorder) RecordDeliveryFailure(string)                         {}
func (nopRecorder) SetDeliveryWorkers(int)                               {}
func (nopRecorder) AddBusyDeliveryWorkers(int)                           {}

const (
	sourceDelivery      = "delivery"
	outcomeDelivered    = "delivered"
	outcomeRetried      = "retried"
	outcomeDeadLettered = "dead_lettered"
	statusNetworkError  = "error"
)

type Worker struct {
	consumer    queue.Consumer
	deadLetters queue.DeadLetterPublisher
	cryptor     *cryptor.Cryptor
	upstream    *url.URL
	client      HTTPClient
	logger      *slog.Logger
	maxAttempts uint64
	now         func() time.Time
	recorder    Recorder
}

func NewWorker(consumer queue.Consumer, deadLetters queue.DeadLetterPublisher, c *cryptor.Cryptor, upstream *url.URL, client HTTPClient, logger *slog.Logger) *Worker {
	return &Worker{
		consumer: consumer, deadLetters: deadLetters, cryptor: c, upstream: upstream,
		client: client, logger: logger, maxAttempts: DefaultMaxAttempts, now: time.Now,
		recorder: nopRecorder{},
	}
}

func (w *Worker) SetRecorder(recorder Recorder) {
	if recorder != nil {
		w.recorder = recorder
	}
}

// SetMaxAttempts moves the threshold beyond which a message stops being
// retried and goes to dead letter. The service uses the default: it serves
// the failure harness, which must walk the whole retry -> DLQ chain without
// waiting for twenty backoff rounds. A non-positive value keeps the default,
// because zero attempts would mean discarding at the first error.
func (w *Worker) SetMaxAttempts(attempts uint64) {
	if attempts > 0 {
		w.maxAttempts = attempts
	}
}

func (w *Worker) Run(ctx context.Context, concurrency int) error {
	if concurrency < 1 {
		concurrency = 1
	}
	w.recorder.SetDeliveryWorkers(concurrency)
	errCh := make(chan error, concurrency)
	for range concurrency {
		go func() { errCh <- w.runLoop(ctx) }()
	}
	for range concurrency {
		if err := <-errCh; err != nil && !errors.Is(err, context.Canceled) {
			return err
		}
	}
	return ctx.Err()
}

func (w *Worker) runLoop(ctx context.Context) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		message, err := w.consumer.Next(ctx)
		if errors.Is(err, queue.ErrNoMessage) {
			continue
		}
		if err != nil {
			w.logger.Warn("JetStream read failed", "error", err)
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(time.Second):
			}
			continue
		}
		w.recorder.AddBusyDeliveryWorkers(1)
		w.process(ctx, message)
		w.recorder.AddBusyDeliveryWorkers(-1)
	}
}

func (w *Worker) process(ctx context.Context, message *queue.Delivery) {
	plain, err := w.cryptor.Decrypt(message.Ciphertext, []byte(message.Kind))
	if err != nil {
		w.toDeadLetter(ctx, message, "decrypt_failed")
		return
	}
	stored, err := envelope.Decode(plain)
	if err != nil {
		w.toDeadLetter(ctx, message, "decode_failed")
		return
	}
	// The stream keeps for days messages written by a gateway whose ingress
	// filtered them differently, or did not filter them at all: the policy must be reapplied
	// here, otherwise waiting for a retry is enough to bypass it.
	tracecontext.Sanitize(stored.Headers)

	startedAt := w.now()
	response, err := w.deliver(ctx, stored, message.Attempts)
	if err != nil && ctx.Err() != nil {
		// The worker is shutting down: the delivery did not fail because of
		// the upstream. Counting it as a failure would move the message one
		// attempt closer to the dead letter — up to isolating a healthy one if it was
		// at the last — and would hold it for the whole backoff, lengthening
		// recovery exactly when another process is ready to pick it up.
		w.requeue(message)
		return
	}
	w.recordUpstream(message.Kind, response, err, w.now().Sub(startedAt))
	if err != nil {
		w.retryOrDeadLetter(ctx, message, "network_error", "")
		return
	}
	defer response.Body.Close()
	if !strings.HasPrefix(message.Kind, "otlp_") || response.StatusCode != 200 {
		_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 64*1024))
	}

	if retryableDelivery(message.Kind, response.StatusCode) {
		w.retryOrDeadLetter(ctx, message, fmt.Sprintf("http_%d", response.StatusCode), response.Header.Get("Retry-After"))
		return
	}
	if response.StatusCode >= 400 || (strings.HasPrefix(message.Kind, "otlp_") && response.StatusCode != 200) {
		w.toDeadLetter(ctx, message, fmt.Sprintf("http_%d", response.StatusCode))
		return
	}
	if strings.HasPrefix(message.Kind, "otlp_") {
		rejected, warning, err := inspectOTLPResponse(message.Kind, response)
		if err != nil {
			w.toDeadLetter(ctx, message, err.Error())
			return
		}
		if rejected > 0 {
			if recorder, ok := w.recorder.(otlpRejectionRecorder); ok {
				recorder.RecordOTLPDeliveryRejected(message.Kind, rejected)
			}
			w.recorder.RecordDeliveryFailure("otlp_partial_rejection")
			w.recorder.RecordDelivery(message.Kind, "partial_success")
			w.logger.Warn("OTLP delivery partially rejected", "request_id", message.ID, "kind", message.Kind, "rejected", rejected)
			w.ack(ctx, message)
			return
		}
		if warning {
			w.recorder.RecordDeliveryFailure("otlp_upstream_warning")
		}
	}
	w.recorder.RecordDelivery(message.Kind, outcomeDelivered)
	w.ack(ctx, message)
}

// recordUpstream tells the received code apart from the failure that prevented
// receiving one: a 429 and a refused connection lead to the same retry but
// not to the same diagnosis.
func (w *Worker) recordUpstream(kind string, response *http.Response, err error, duration time.Duration) {
	status := statusNetworkError
	if err == nil && response != nil {
		status = strconv.Itoa(response.StatusCode)
		if delay := upstream.ParseRetryAfter(response.Header.Get("Retry-After"), w.now()); delay > 0 {
			w.recorder.RecordRetryAfter(sourceDelivery, delay)
		}
	}
	w.recorder.RecordUpstream(sourceDelivery, kind, status, duration)
}

func (w *Worker) deliver(ctx context.Context, stored envelope.Request, attempts uint64) (*http.Response, error) {
	target := *w.upstream
	target.Path = stored.Path
	target.RawQuery = stored.RawQuery
	request, err := http.NewRequestWithContext(ctx, stored.Method, target.String(), bytes.NewReader(stored.Body))
	if err != nil {
		return nil, err
	}
	for name, value := range stored.Headers {
		request.Header.Set(name, value)
	}
	if stored.RemoteAddr != "" {
		request.Header.Set("X-Forwarded-For", stored.RemoteAddr)
	}
	request.Header.Set("X-Forwarded-Proto", "https")
	request.Header.Set("X-CloseYourIt-Delivery-Attempt", strconv.FormatUint(attempts, 10))
	return w.client.Do(request)
}

// requeue makes the message available again without waiting: there is nothing to
// calm down, the work just has to be handed to whoever is still standing.
func (w *Worker) requeue(message *queue.Delivery) {
	if err := message.Retry(0); err != nil {
		w.logger.Error("redelivery during shutdown failed", "request_id", message.ID, "error", err)
	}
}

func (w *Worker) retryOrDeadLetter(ctx context.Context, message *queue.Delivery, reason, retryAfter string) {
	if message.Attempts >= w.maxAttempts {
		w.toDeadLetter(ctx, message, reason+"_max_attempts")
		return
	}
	w.recorder.RecordDelivery(message.Kind, outcomeRetried)
	w.recorder.RecordDeliveryFailure(reason)
	delay := RetryDelay(message.Attempts, retryAfter, w.now())
	if strings.HasPrefix(message.Kind, "otlp_") && upstream.ParseRetryAfter(retryAfter, w.now()) <= 0 {
		delay = time.Duration(float64(delay) * (0.8 + rand.Float64()*0.4))
		if delay > time.Hour {
			delay = time.Hour
		}
	}
	if err := message.Retry(delay); err != nil {
		w.logger.Error("JetStream NACK failed", "request_id", message.ID, "delay", delay, "error", err)
	}
}

func (w *Worker) toDeadLetter(ctx context.Context, delivery *queue.Delivery, reason string) {
	w.recorder.RecordDelivery(delivery.Kind, outcomeDeadLettered)
	w.recorder.RecordDeliveryFailure(reason)
	message := queue.Message{ID: delivery.ID, Kind: delivery.Kind, Ciphertext: delivery.Ciphertext}
	if err := w.deadLetters.DeadLetter(ctx, message, reason); err != nil {
		w.logger.Error("dead letter publish failed", "request_id", delivery.ID, "reason", reason, "error", err)
		_ = delivery.Retry(time.Minute)
		return
	}
	w.ack(ctx, delivery)
}

func (w *Worker) ack(ctx context.Context, message *queue.Delivery) {
	ackCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if err := message.Ack(ackCtx); err != nil {
		w.logger.Error("JetStream ACK failed", "request_id", message.ID, "error", err)
	}
}

func isRetryable(status int) bool {
	return status == http.StatusRequestTimeout || status == http.StatusTooEarly || status == http.StatusTooManyRequests || status >= 500
}

func RetryDelay(attempt uint64, retryAfter string, now time.Time) time.Duration {
	if parsed := upstream.ParseRetryAfter(retryAfter, now); parsed > 0 {
		if parsed > time.Hour {
			return time.Hour
		}
		return parsed
	}
	delays := []time.Duration{5 * time.Second, 30 * time.Second, 2 * time.Minute, 10 * time.Minute, 30 * time.Minute, time.Hour}
	index := int(attempt)
	if index < 1 {
		index = 1
	}
	if index > len(delays) {
		index = len(delays)
	}
	return delays[index-1]
}

// OTLP has its own retry table: HTTP 500 is permanent, unlike native ingest.
func retryableDelivery(kind string, status int) bool {
	if strings.HasPrefix(kind, "otlp_") {
		return status == 429 || status == 502 || status == 503 || status == 504
	}
	return isRetryable(status)
}

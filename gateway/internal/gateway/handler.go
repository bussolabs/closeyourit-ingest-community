package gateway

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/bussolabs/closeyourit-ingest-community/gateway/internal/cryptor"
	"github.com/bussolabs/closeyourit-ingest-community/gateway/internal/envelope"
	"github.com/bussolabs/closeyourit-ingest-community/gateway/internal/queue"
	"github.com/bussolabs/closeyourit-ingest-community/gateway/internal/tracecontext"
	"github.com/bussolabs/closeyourit-ingest-community/gateway/internal/upstream"
	"github.com/bussolabs/closeyourit-ingest-community/gateway/internal/version"
)

const DefaultMaxBodyBytes int64 = 5 * 1024 * 1024
const NativeMaxBodyBytes int64 = 20 * 1024 * 1024
const MaxBufferedRequests = 4
const AdmissionHeader = "X-CloseYourIt-Ingest-Authorized"

// forwardedHeaders decides what gets in: everything else in the client's
// request stops here. For the three trace context headers admission is not
// enough, the value must then pass the tracecontext policy.
var forwardedHeaders = []string{
	"Authorization", "Origin", "Content-Type", "Content-Encoding", "User-Agent",
	"X-Sentry-Auth", "Sentry-Trace", "X-Request-Id",
	tracecontext.HeaderTraceparent, tracecontext.HeaderTracestate, tracecontext.HeaderBaggage,
}

type HTTPClient interface {
	Do(*http.Request) (*http.Response, error)
}

// Recorder receives the operational facts of ingress. The gateway states what
// happened, not how it should be published: whoever observes nothing passes the
// no-op and the request path stays identical.
type Recorder interface {
	RecordRequest(kind, outcome string)
	RecordRejected(reason string)
	RecordUpstream(source, kind, status string, duration time.Duration)
	RecordPublish(kind string, duration time.Duration, err error)
	RecordRetryAfter(source string, delay time.Duration)
	SetReadiness(directProxyHealthy, queueConnected, draining bool)
}

type nopRecorder struct{}

func (nopRecorder) RecordRequest(string, string)                         {}
func (nopRecorder) RecordRejected(string)                                {}
func (nopRecorder) RecordUpstream(string, string, string, time.Duration) {}
func (nopRecorder) RecordPublish(string, time.Duration, error)           {}
func (nopRecorder) RecordRetryAfter(string, time.Duration)               {}
func (nopRecorder) SetReadiness(bool, bool, bool)                        {}

// Sources and outcomes are metric labels: keeping a single copy of them
// prevents an alert from chasing a value the code no longer emits.
const (
	sourceDirect       = "direct"
	outcomeDirect      = "direct"
	outcomeQueued      = "queued"
	outcomeDropped     = "dropped"
	statusNetworkError = "error"
)

type Handler struct {
	bodySlots      chan struct{}
	nativeSlots    chan struct{}
	upstream       *url.URL
	client         HTTPClient
	publisher      queue.Publisher
	cryptor        *cryptor.Cryptor
	logger         *slog.Logger
	maxBody        int64
	now            func() time.Time
	newID          func() (string, error)
	queueOnCode    func(int) bool
	queueConnected func() bool
	recorder       Recorder
	// directProxyFailedAt is the instant of the last failed forward, 0 if there
	// is no recent one: no active probe towards the upstream, which would generate
	// artificial traffic. The observation expires on its own because a gateway
	// taken out of the pool does not receive the traffic to verify its recovery with.
	directProxyFailedAt atomic.Int64
	draining            atomic.Bool
}

// directProxyFailureTTL covers more than one health check round of the reverse proxy,
// enough not to flap on every isolated error.
const directProxyFailureTTL = 30 * time.Second

func NewHandler(upstream *url.URL, client HTTPClient, publisher queue.Publisher, c *cryptor.Cryptor, logger *slog.Logger) *Handler {
	handler := &Handler{
		bodySlots:   make(chan struct{}, MaxBufferedRequests),
		nativeSlots: make(chan struct{}, 2),
		upstream:    upstream, client: client, publisher: publisher, cryptor: c, logger: logger,
		maxBody: DefaultMaxBodyBytes, now: time.Now, newID: randomID,
		queueOnCode:    func(code int) bool { return code == 408 || code == 425 || code == 429 || code >= 500 },
		queueConnected: func() bool { return true },
		recorder:       nopRecorder{},
	}
	return handler
}

func (h *Handler) SetRecorder(recorder Recorder) {
	if recorder != nil {
		h.recorder = recorder
	}
}

func (h *Handler) SetQueueConnectedFunc(queueConnected func() bool) {
	if queueConnected != nil {
		h.queueConnected = queueConnected
	}
}

// BeginShutdown takes the gateway out of the load balancer pool without turning
// off liveness: the process stays alive while it drains the in-flight requests.
func (h *Handler) BeginShutdown() {
	h.draining.Store(true)
}

// recordDirectProxy updates the state of the direct path only when the outcome
// says something about the upstream: a request abandoned by the client fails
// because of us, not of it, and must not downgrade a healthy upstream.
func (h *Handler) recordDirectProxy(ctx context.Context, delivered bool) {
	if !delivered && ctx.Err() != nil {
		return
	}
	if delivered {
		h.directProxyFailedAt.Store(0)
		return
	}
	h.directProxyFailedAt.Store(h.now().UnixNano())
}

// At startup, and again after a failure expires, the direct path is
// declared healthy: a path never tried is not a broken path.
func (h *Handler) directProxyHealthy() bool {
	failedAt := h.directProxyFailedAt.Load()
	return failedAt == 0 || h.now().Sub(time.Unix(0, failedAt)) >= directProxyFailureTTL
}

func (h *Handler) readiness() (int, map[string]any) {
	queueConnected := h.queueConnected()
	directProxyHealthy := h.directProxyHealthy()
	accepting := directProxyHealthy

	status := "ready"
	switch {
	case h.draining.Load():
		status, accepting = "draining", false
	case !directProxyHealthy:
		status = "unavailable"
	case !queueConnected || !directProxyHealthy:
		status = "degraded"
	}

	h.recorder.SetReadiness(directProxyHealthy, queueConnected, h.draining.Load())

	code := http.StatusOK
	if !accepting {
		code = http.StatusServiceUnavailable
	}
	return code, map[string]any{
		"status": status, "accepting": accepting,
		"direct_proxy_healthy": directProxyHealthy, "queue_connected": queueConnected,
	}
}

// RefreshReadiness republishes the state of the two paths without waiting for an
// external probe: if the reverse proxy stops polling /ready, the gauges
// would freeze exactly when they are needed to understand why.
func (h *Handler) RefreshReadiness() {
	_, _ = h.readiness()
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if isControlPath(r.URL.Path) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": map[string]string{"code": "R405-INGEST-GATEWAY-001", "message": "Method not allowed"}})
			return
		}
		switch r.URL.Path {
		case "/up":
			writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
			return
		case "/version":
			writeJSON(w, http.StatusOK, version.Info())
			return
		case "/ready":
			code, payload := h.readiness()
			writeJSON(w, code, payload)
			return
		}
		// /healthz is the legacy alias: it keeps the old NATS gate so as not to
		// silently change the existing consumers.
		if !h.queueConnected() {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"status": "unavailable"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"status": "ok"})
		return
	}
	if r.Method != http.MethodPost {
		h.recorder.RecordRejected("method_not_allowed")
		writeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": map[string]string{"code": "R405-INGEST-GATEWAY-001", "message": "Method not allowed"}})
		return
	}
	kind, allowed := classifyRoute(r.URL.Path)
	if !allowed {
		h.recorder.RecordRejected("not_found")
		writeJSON(w, http.StatusNotFound, map[string]any{"error": map[string]string{"code": "R404-INGEST-GATEWAY-001", "message": "Unsupported endpoint"}})
		return
	}

	// Reserve the worst-case body and serialization budget before reading any bytes.
	select {
	case h.bodySlots <- struct{}{}:
		defer func() { <-h.bodySlots }()
	default:
		h.recorder.RecordRejected("buffer_budget")
		w.Header().Set("Retry-After", "1")
		w.Header().Set("Connection", "close")
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": map[string]string{"code": "R503-INGEST-GATEWAY-003", "message": "Ingest buffer capacity reached"}})
		return
	}

	maxBody := h.maxBody
	if kind == "minidump" {
		select {
		case h.nativeSlots <- struct{}{}:
			defer func() { <-h.nativeSlots }()
		default:
			h.recorder.RecordRejected("native_buffer_budget")
			w.Header().Set("Retry-After", "1")
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "Native ingestion capacity reached"})
			return
		}
		maxBody = NativeMaxBodyBytes
	}
	body, err := readBody(r.Body, maxBody)
	if err != nil {
		h.recorder.RecordRejected("body_too_large")
		writeJSON(w, http.StatusRequestEntityTooLarge, map[string]any{"error": map[string]string{"code": "R413-INGEST-GATEWAY-001", "message": "Payload too large"}})
		return
	}

	requestID, err := h.newID()
	if err != nil {
		h.recorder.RecordRejected("request_id_unavailable")
		h.logger.Error("request id generation failed", "error", err)
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": map[string]string{"code": "R503-INGEST-GATEWAY-001", "message": "Ingest temporarily unavailable"}})
		return
	}

	stored := envelope.Request{
		Method: http.MethodPost, Path: r.URL.Path, RawQuery: r.URL.RawQuery,
		Headers: selectedHeaders(r.Header), RemoteAddr: clientIP(r), ReceivedAt: h.now().UTC(), Body: body,
	}
	stored.Headers["X-CloseYourIt-Request-Id"] = requestID

	forwardedAt := h.now()
	upstreamResponse, upstreamErr := h.forward(r.Context(), stored)
	h.recordUpstream(sourceDirect, kind, upstreamResponse, upstreamErr, h.now().Sub(forwardedAt))
	directDelivered := upstreamErr == nil && !h.queueOnCode(upstreamResponse.StatusCode)
	h.recordDirectProxy(r.Context(), directDelivered)
	if directDelivered {
		h.recorder.RecordRequest(kind, outcomeDirect)
		copyResponse(w, upstreamResponse)
		return
	}

	// Raw diagnostic bytes may only be retried by the client, never written to a durable queue.
	isEnvelope := kind == "sentry" && strings.HasSuffix(strings.TrimSuffix(r.URL.Path, "/"), "/envelope")
	if kind == "minidump" || isEnvelope {
		h.recorder.RecordRequest(kind, outcomeDropped)
		if upstreamResponse != nil {
			copyResponse(w, upstreamResponse)
		} else {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "Raw diagnostic admission unavailable; retry later"})
		}
		return
	}

	// A transport failure or a pre-authentication throttle proves no authority to occupy the queue.
	// Only the fixed upstream can assert admission, after credential, scope and Origin checks.
	if upstreamErr != nil || upstreamResponse == nil || upstreamResponse.Header.Get(AdmissionHeader) != "true" || upstreamResponse.StatusCode == http.StatusTooManyRequests {
		h.recorder.RecordRequest(kind, outcomeDropped)
		if upstreamResponse != nil {
			copyResponse(w, upstreamResponse)
		} else {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": map[string]string{"code": "R503-INGEST-GATEWAY-004", "message": "Ingest authorization unavailable; retry later"}})
		}
		return
	}

	publishedAt := h.now()
	err = h.enqueue(r.Context(), requestID, kind, stored)
	h.recorder.RecordPublish(kind, h.now().Sub(publishedAt), err)
	if err != nil {
		h.recorder.RecordRequest(kind, outcomeDropped)
		h.logger.Error("JetStream fallback failed", "request_id", requestID, "kind", kind, "error", err)
		if upstreamResponse != nil {
			copyResponse(w, upstreamResponse)
			return
		}
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": map[string]string{"code": "R503-INGEST-GATEWAY-002", "message": "Could not store the message"}})
		return
	}
	if upstreamResponse != nil {
		_ = upstreamResponse.Body.Close()
	}

	h.recorder.RecordRequest(kind, outcomeQueued)
	w.Header().Set("X-CloseYourIt-Queued", "true")
	w.Header().Set("X-CloseYourIt-Request-Id", requestID)
	if kind == "sentry" {
		writeJSON(w, http.StatusOK, map[string]any{"id": requestID, "queued": true})
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"data": map[string]any{"queued": true, "id": requestID}})
}

// recordUpstream translates the upstream outcome into labels: the code when
// there is a response, "error" when the request did not even arrive. They are
// two different failures and must be kept apart, because the cure is not the same.
func (h *Handler) recordUpstream(source, kind string, response *http.Response, err error, duration time.Duration) {
	status := statusNetworkError
	if err == nil && response != nil {
		status = strconv.Itoa(response.StatusCode)
		if delay := upstream.ParseRetryAfter(response.Header.Get("Retry-After"), h.now()); delay > 0 {
			h.recorder.RecordRetryAfter(source, delay)
		}
	}
	h.recorder.RecordUpstream(source, kind, status, duration)
}

func isControlPath(path string) bool {
	switch path {
	case "/up", "/ready", "/version", "/healthz":
		return true
	default:
		return false
	}
}

func (h *Handler) forward(ctx context.Context, stored envelope.Request) (*http.Response, error) {
	target := *h.upstream
	target.Path = stored.Path
	target.RawQuery = stored.RawQuery
	req, err := http.NewRequestWithContext(ctx, stored.Method, target.String(), bytes.NewReader(stored.Body))
	if err != nil {
		return nil, err
	}
	for name, value := range stored.Headers {
		req.Header.Set(name, value)
	}
	if stored.RemoteAddr != "" {
		req.Header.Set("X-Forwarded-For", stored.RemoteAddr)
	}
	req.Header.Set("X-Forwarded-Proto", "https")
	return h.client.Do(req)
}

func (h *Handler) enqueue(ctx context.Context, requestID, kind string, stored envelope.Request) error {
	plain, err := envelope.Encode(stored)
	if err != nil {
		return err
	}
	ciphertext, err := h.cryptor.Encrypt(plain, []byte(kind))
	if err != nil {
		return err
	}
	return h.publisher.Publish(ctx, queue.Message{ID: requestID, Kind: kind, Ciphertext: ciphertext})
}

func readBody(body io.ReadCloser, max int64) ([]byte, error) {
	defer body.Close()
	data, err := io.ReadAll(io.LimitReader(body, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > max {
		return nil, errors.New("body too large")
	}
	return data, nil
}

func selectedHeaders(headers http.Header) map[string]string {
	selected := make(map[string]string, len(forwardedHeaders))
	for _, name := range forwardedHeaders {
		if value := headers.Get(name); value != "" {
			selected[name] = value
		}
	}
	// The policy applies before persistence: only what the gateway would be
	// entitled to forward anyway ends up in the envelope, so a message fished
	// back out of the queue does not bring a rejected value back to life.
	if origins := headers.Values("Origin"); len(origins) > 1 {
		selected["Origin"] = strings.Join(origins, ",")
	}
	tracecontext.Sanitize(selected)
	return selected
}

func clientIP(r *http.Request) string {
	if forwarded := strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-For"), ",")[0]); forwarded != "" {
		return forwarded
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}

func randomID() (string, error) {
	data := make([]byte, 16)
	if _, err := rand.Read(data); err != nil {
		return "", fmt.Errorf("random id: %w", err)
	}
	return hex.EncodeToString(data), nil
}

func copyResponse(w http.ResponseWriter, response *http.Response) {
	defer response.Body.Close()
	for _, name := range []string{"Content-Type", "Retry-After", "X-RateLimit-Limit", "X-RateLimit-Remaining"} {
		if value := response.Header.Get(name); value != "" {
			w.Header().Set(name, value)
		}
	}
	w.WriteHeader(response.StatusCode)
	_, _ = io.Copy(w, io.LimitReader(response.Body, 2*1024*1024))
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

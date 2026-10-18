package chaos

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bussolabs/closeyourit-ingest-community/gateway/internal/cryptor"
	"github.com/bussolabs/closeyourit-ingest-community/gateway/internal/delivery"
	"github.com/bussolabs/closeyourit-ingest-community/gateway/internal/gateway"
	"github.com/bussolabs/closeyourit-ingest-community/gateway/internal/natsstore"
	"github.com/bussolabs/closeyourit-ingest-community/gateway/internal/queue"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

// The NATS configuration is not rewritten here: the harness loads the one
// the container actually mounts. A lowered max_payload or a disabled jetstream
// would make these tests fail instead of finding out in production with a
// rejected 5 MiB payload.
const natsConfigPath = "../../../nats-server.conf"

// jetStreamMaxStoreFromConfig leaves the cap declared in the file standing:
// lowering it below the sum of the two streams' quotas would prevent the gateway
// from creating them, which is exactly the failure verified by
// TestSetupRefusesToStartWhenTheDiskDoesNotCoverTheDeclaredQuotas. JetStream
// preallocates nothing, so the high limit does not fill the temporary directory.
const jetStreamMaxStoreFromConfig int64 = 0

const testNATSPassword = "harness-nats-password"

type backendMode int32

const (
	// backendHealthy answers like CloseYourIt when it accepts the telemetry.
	backendHealthy backendMode = iota
	// backendServerError is the live upstream that refuses: 503, the case the
	// gateway must queue.
	backendServerError
	// backendNetworkDrop is the upstream that does not answer at all: the connection
	// dies without an HTTP code. A failure different from the 503 and with a different diagnosis.
	backendNetworkDrop
	// backendRateLimited is the 429 with Retry-After: the upstream asks to
	// slow down, not to stop.
	backendRateLimited
	// backendPermanentError is the definitive refusal: retrying it changes
	// nothing, the message must be isolated.
	backendPermanentError
)

type recordedRequest struct {
	RequestID string
	Path      string
	BodySum   string
	BodyBytes int
	Attempt   string
	At        time.Time
}

// fakeBackend is CloseYourIt as seen from the gateway: it records every request by
// request id — the key the real backend uses to recognize a duplicate — and
// changes behavior on command.
type fakeBackend struct {
	server   *httptest.Server
	address  string
	mode     atomic.Int32
	latency  atomic.Int64
	mu       sync.Mutex
	requests []recordedRequest
}

func newFakeBackend(t *testing.T) *fakeBackend {
	t.Helper()
	backend := &fakeBackend{}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listener backend: %v", err)
	}
	backend.address = listener.Addr().String()
	backend.serve(listener)
	t.Cleanup(backend.stop)
	return backend
}

func (b *fakeBackend) serve(listener net.Listener) {
	unstarted := httptest.NewUnstartedServer(http.HandlerFunc(b.handle))
	_ = unstarted.Listener.Close()
	unstarted.Listener = listener
	unstarted.Start()
	b.server = unstarted
}

func (b *fakeBackend) handle(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	sum := sha256.Sum256(body)
	b.mu.Lock()
	b.requests = append(b.requests, recordedRequest{
		RequestID: r.Header.Get("X-CloseYourIt-Request-Id"),
		Path:      r.URL.Path,
		BodySum:   hex.EncodeToString(sum[:]),
		BodyBytes: len(body),
		Attempt:   r.Header.Get("X-CloseYourIt-Delivery-Attempt"),
		At:        time.Now(),
	})
	b.mu.Unlock()

	if latency := time.Duration(b.latency.Load()); latency > 0 {
		time.Sleep(latency)
	}

	switch backendMode(b.mode.Load()) {
	case backendNetworkDrop:
		// The connection drops without a response: the gateway must treat it as
		// a network failure, not as an application code.
		hijacker, ok := w.(http.Hijacker)
		if !ok {
			panic(http.ErrAbortHandler)
		}
		connection, _, err := hijacker.Hijack()
		if err != nil {
			panic(http.ErrAbortHandler)
		}
		_ = connection.Close()
	case backendServerError:
		w.Header().Set(gateway.AdmissionHeader, "true")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"error":{"code":"R503-CLOSEYOURIT-001"}}`))
	case backendRateLimited:
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Retry-After", "1")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"error":{"code":"R429-CLOSEYOURIT-001"}}`))
	case backendPermanentError:
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":{"code":"R401-CLOSEYOURIT-001"}}`))
	default:
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"data":{"accepted":1}}`))
	}
}

func (b *fakeBackend) setMode(mode backendMode) { b.mode.Store(int32(mode)) }

func (b *fakeBackend) setLatency(latency time.Duration) { b.latency.Store(int64(latency)) }

// stop and start turn CloseYourIt off and on again on the same port: while off, the
// gateway gets refused connections, which is the real failure of an upstream
// that is down — different from an error response.
func (b *fakeBackend) stop() {
	if b.server == nil {
		return
	}
	b.server.Close()
	b.server = nil
}

func (b *fakeBackend) start(t *testing.T) {
	t.Helper()
	if b.server != nil {
		return
	}
	listener, err := net.Listen("tcp", b.address)
	if err != nil {
		t.Fatalf("reopening backend on %s: %v", b.address, err)
	}
	b.serve(listener)
}

func (b *fakeBackend) recorded() []recordedRequest {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]recordedRequest(nil), b.requests...)
}

type harnessOptions struct {
	rateLimit int
}

type harnessOption func(*harnessOptions)

func withRateLimit(limit int) harnessOption {
	return func(options *harnessOptions) { options.rateLimit = limit }
}

type harness struct {
	t           *testing.T
	options     harnessOptions
	natsServer  *server.Server
	storeDir    string
	natsPort    int
	connection  *nats.Conn
	js          jetstream.JetStream
	store       *natsstore.Store
	backend     *fakeBackend
	upstream    *url.URL
	cryptor     *cryptor.Cryptor
	logger      *slog.Logger
	gatewayHTTP *httptest.Server
	// The gateway address does not change from one restart to the next: real
	// clients do not rediscover a new port, and a test that sends traffic during
	// the restart must be able to keep knocking at the same place.
	gatewayAddress string
	gatewayURL     string
	client         *http.Client
}

func newHarness(t *testing.T, opts ...harnessOption) *harness {
	t.Helper()
	if testing.Short() {
		t.Skip("the load and failure suite starts NATS: skipped with -short")
	}

	options := harnessOptions{}
	for _, apply := range opts {
		apply(&options)
	}

	backend := newFakeBackend(t)
	upstream, err := url.Parse("http://" + backend.address)
	if err != nil {
		t.Fatalf("URL upstream: %v", err)
	}
	key := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{11}, 32))
	envelopeCryptor, err := cryptor.New(key)
	if err != nil {
		t.Fatalf("cryptor: %v", err)
	}

	gatewayAddress := fmt.Sprintf("127.0.0.1:%d", freePort(t))
	h := &harness{
		t: t, options: options, storeDir: t.TempDir(), natsPort: freePort(t),
		backend: backend, upstream: upstream, cryptor: envelopeCryptor,
		logger:         slog.New(slog.NewTextHandler(io.Discard, nil)),
		gatewayAddress: gatewayAddress, gatewayURL: "http://" + gatewayAddress,
		client: &http.Client{Timeout: 30 * time.Second},
	}
	h.startNATS()
	h.connect()
	h.startGateway()
	t.Cleanup(h.close)
	return h
}

// startNATSServer starts the broker with the container configuration: of the
// production state only address, directory and JetStream cap change, that is
// the three things a temporary directory cannot inherit.
func startNATSServer(t *testing.T, storeDir string, port int, jetStreamMaxStore int64) *server.Server {
	t.Helper()
	t.Setenv("NATS_PASSWORD", testNATSPassword)
	options, err := server.ProcessConfigFile(natsConfigPath)
	if err != nil {
		t.Fatalf("reading %s: %v", natsConfigPath, err)
	}
	options.Host = "127.0.0.1"
	options.Port = port
	options.HTTPHost = "127.0.0.1"
	options.HTTPPort = 0
	options.StoreDir = filepath.Join(storeDir, "jetstream")
	if jetStreamMaxStore > 0 {
		options.JetStreamMaxStore = jetStreamMaxStore
	}
	options.NoLog = true
	options.NoSigs = true

	natsServer, err := server.NewServer(options)
	if err != nil {
		t.Fatalf("starting NATS: %v", err)
	}
	go natsServer.Start()
	if !natsServer.ReadyForConnections(15 * time.Second) {
		t.Fatal("NATS not ready within 15s")
	}
	return natsServer
}

func connectNATS(t *testing.T, port int) (*nats.Conn, jetstream.JetStream) {
	t.Helper()
	connection, err := nats.Connect(fmt.Sprintf("nats://127.0.0.1:%d", port),
		nats.UserInfo("ingest", testNATSPassword),
		nats.Name("harness-chaos"),
		nats.Timeout(5*time.Second),
		nats.MaxReconnects(-1),
		nats.ReconnectWait(100*time.Millisecond),
	)
	if err != nil {
		t.Fatalf("NATS connection: %v", err)
	}
	js, err := jetstream.New(connection)
	if err != nil {
		t.Fatalf("client JetStream: %v", err)
	}
	return connection, js
}

func (h *harness) startNATS() {
	h.t.Helper()
	h.natsServer = startNATSServer(h.t, h.storeDir, h.natsPort, jetStreamMaxStoreFromConfig)
}

func (h *harness) connect() {
	h.t.Helper()
	connection, js := connectNATS(h.t, h.natsPort)
	setupContext, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	store, err := natsstore.Setup(setupContext, js)
	if err != nil {
		h.t.Fatalf("setup stream: %v", err)
	}
	h.connection, h.js, h.store = connection, js, store
}

// startGateway mounts the gateway as in production: same handler, same
// forwarding timeout, same gate on the queue connection.
func (h *harness) startGateway() {
	h.t.Helper()
	directClient := &http.Client{Timeout: 3 * time.Second}
	handler := gateway.NewHandler(h.upstream, directClient, h.store, h.cryptor, h.logger)
	handler.SetQueueConnectedFunc(h.connection.IsConnected)

	var entrypoint http.Handler = handler
	if h.options.rateLimit > 0 {
		limiter := gateway.NewRateLimiter(h.options.rateLimit, time.Minute)
		entrypoint = limiter.Middleware(handler)
	}
	listener, err := net.Listen("tcp", h.gatewayAddress)
	if err != nil {
		h.t.Fatalf("gateway listening on %s: %v", h.gatewayAddress, err)
	}
	unstarted := httptest.NewUnstartedServer(entrypoint)
	_ = unstarted.Listener.Close()
	unstarted.Listener = listener
	unstarted.Start()
	h.gatewayHTTP = unstarted
}

// restartGateway redoes the gateway process: new queue connection and handler,
// queue and disk intact. It is the redeploy, not the disaster.
func (h *harness) restartGateway() {
	h.t.Helper()
	h.gatewayHTTP.Close()
	h.connection.Close()
	h.connect()
	h.startGateway()
}

// restartNATS shuts the broker down and starts it again on the same port and the same
// store: what survives here is the operational definition of RPO.
func (h *harness) restartNATS() {
	h.t.Helper()
	h.natsServer.Shutdown()
	h.natsServer.WaitForShutdown()
	h.startNATS()
	h.waitFor(20*time.Second, "gateway reconnection to NATS", func() bool {
		return h.connection.IsConnected()
	})
}

// stopNATS leaves the gateway without a queue: from here on it can only forward or
// refuse, and must not pretend to have kept anything.
func (h *harness) stopNATS() {
	h.t.Helper()
	h.natsServer.Shutdown()
	h.natsServer.WaitForShutdown()
}

func (h *harness) close() {
	if h.gatewayHTTP != nil {
		h.gatewayHTTP.Close()
	}
	if h.connection != nil {
		h.connection.Close()
	}
	if h.natsServer != nil {
		h.natsServer.Shutdown()
		h.natsServer.WaitForShutdown()
	}
}

// compressAckWait shortens the window after which JetStream redelivers an
// unacknowledged message. In production it is 30 seconds; the harness
// compresses it because the behavior to verify is the redelivery, not
// the wait.
func (h *harness) compressAckWait(ackWait time.Duration) {
	h.t.Helper()
	config := natsstore.DeliveryConsumerConfig()
	config.AckWait = ackWait
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := h.js.CreateOrUpdateConsumer(ctx, natsstore.IngestStream, config); err != nil {
		h.t.Fatalf("updating AckWait: %v", err)
	}
}

// shrinkIngestStream brings the stream quota down to a reachable value:
// actually filling 25 GiB proves nothing that filling a small one does not,
// since DiscardNew is what decides.
func (h *harness) shrinkIngestStream(maxBytes int64) {
	h.t.Helper()
	config := natsstore.IngestStreamConfig()
	config.MaxBytes = maxBytes
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := h.js.UpdateStream(ctx, config); err != nil {
		h.t.Fatalf("stream quota reduction: %v", err)
	}
}

type postResult struct {
	StatusCode int
	Queued     bool
	RequestID  string
	Body       string
}

func (h *harness) post(path string, body []byte) postResult {
	h.t.Helper()
	result, err := h.tryPost(path, body)
	if err != nil {
		h.t.Fatalf("POST %s: %v", path, err)
	}
	return result
}

func (h *harness) tryPost(path string, body []byte) (postResult, error) {
	request, err := http.NewRequest(http.MethodPost, h.gatewayURL+path, bytes.NewReader(body))
	if err != nil {
		return postResult{}, err
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer token-di-prova")
	response, err := h.client.Do(request)
	if err != nil {
		return postResult{}, err
	}
	defer response.Body.Close()
	payload, err := io.ReadAll(io.LimitReader(response.Body, 64*1024))
	if err != nil {
		return postResult{}, err
	}
	return postResult{
		StatusCode: response.StatusCode,
		Queued:     response.Header.Get("X-CloseYourIt-Queued") == "true",
		RequestID:  response.Header.Get("X-CloseYourIt-Request-Id"),
		Body:       string(payload),
	}, nil
}

func (h *harness) get(path string) (int, string) {
	h.t.Helper()
	response, err := h.client.Get(h.gatewayURL + path)
	if err != nil {
		h.t.Fatalf("GET %s: %v", path, err)
	}
	defer response.Body.Close()
	payload, _ := io.ReadAll(io.LimitReader(response.Body, 64*1024))
	return response.StatusCode, string(payload)
}

func (h *harness) stats() queue.StoreStats {
	h.t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	stats, err := h.store.Stats(ctx)
	if err != nil {
		h.t.Fatalf("reading queue state: %v", err)
	}
	return stats
}

func (h *harness) streamStats(name string) queue.StreamStats {
	h.t.Helper()
	for _, stream := range h.stats().Streams {
		if stream.Name == name {
			return stream
		}
	}
	h.t.Fatalf("stream %s missing", name)
	return queue.StreamStats{}
}

func (h *harness) ingestDepth() uint64 {
	return h.streamStats(natsstore.IngestStream).Messages
}

func (h *harness) deadLetterDepth() uint64 {
	return h.streamStats(natsstore.DeadLetterStream).Messages
}

// interceptingConsumer is the worker that dies between delivery and acknowledgement:
// the ACK never reaches the broker, which after AckWait will hand out the same message again.
type interceptingConsumer struct {
	inner      queue.Consumer
	swallowAck atomic.Bool
	delivered  atomic.Int64
}

func (c *interceptingConsumer) Next(ctx context.Context) (*queue.Delivery, error) {
	message, err := c.inner.Next(ctx)
	if message == nil {
		return message, err
	}
	c.delivered.Add(1)
	if c.swallowAck.Load() {
		message.Ack = func(context.Context) error { return nil }
	}
	return message, err
}

type workerHandle struct {
	cancel context.CancelFunc
	done   chan struct{}
}

// stop is the gateway receiving SIGTERM: the worker stops taking work and
// what it had in hand goes back to the queue.
func (w *workerHandle) stop() {
	w.cancel()
	<-w.done
}

type workerOptions struct {
	concurrency     int
	maxAttempts     uint64
	consumer        queue.Consumer
	deliveryTimeout time.Duration
}

type workerOption func(*workerOptions)

func withConcurrency(concurrency int) workerOption {
	return func(options *workerOptions) { options.concurrency = concurrency }
}

func withMaxAttempts(attempts uint64) workerOption {
	return func(options *workerOptions) { options.maxAttempts = attempts }
}

func withConsumer(consumer queue.Consumer) workerOption {
	return func(options *workerOptions) { options.consumer = consumer }
}

func (h *harness) startWorker(opts ...workerOption) *workerHandle {
	h.t.Helper()
	options := workerOptions{concurrency: 2, deliveryTimeout: 15 * time.Second}
	for _, apply := range opts {
		apply(&options)
	}
	consumer := options.consumer
	if consumer == nil {
		consumer = h.store
	}

	worker := delivery.NewWorker(consumer, h.store, h.cryptor, h.upstream,
		&http.Client{Timeout: options.deliveryTimeout}, h.logger)
	if options.maxAttempts > 0 {
		worker.SetMaxAttempts(options.maxAttempts)
	}

	ctx, cancel := context.WithCancel(context.Background())
	handle := &workerHandle{cancel: cancel, done: make(chan struct{})}
	go func() {
		defer close(handle.done)
		_ = worker.Run(ctx, options.concurrency)
	}()
	h.t.Cleanup(func() {
		cancel()
		<-handle.done
	})
	return handle
}

func (h *harness) waitFor(timeout time.Duration, what string, condition func() bool) time.Duration {
	h.t.Helper()
	startedAt := time.Now()
	deadline := startedAt.Add(timeout)
	for time.Now().Before(deadline) {
		if condition() {
			return time.Since(startedAt)
		}
		time.Sleep(20 * time.Millisecond)
	}
	h.t.Fatalf("timeout after %s waiting for: %s", timeout, what)
	return 0
}

func freePort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("free port: %v", err)
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port
}

// telemetryBody builds a payload representative of real traffic: a
// batch of application logs, not a random blob, because the stream's S2
// compression treats the two very differently and capacity is measured on
// what clients actually send.
func telemetryBody(index int) []byte {
	var buffer bytes.Buffer
	buffer.WriteString(`{"logs":[`)
	for entry := range 8 {
		if entry > 0 {
			buffer.WriteByte(',')
		}
		fmt.Fprintf(&buffer,
			`{"level":"error","message":"timeout on external call","request_id":"req-%d-%d",`+
				`"timestamp":"2026-08-22T10:%02d:%02dZ","context":{"controller":"Api::V1::EventsController",`+
				`"action":"create","duration_ms":%d,"host":"web-%d"}}`,
			index, entry, index%60, entry*7%60, 120+entry*13, index%4)
	}
	buffer.WriteString(`]}`)
	return buffer.Bytes()
}

func payloadOfSize(size int) []byte {
	prefix := []byte(`{"logs":[{"level":"info","message":"`)
	suffix := []byte(`"}]}`)
	filler := bytes.Repeat([]byte("x"), size-len(prefix)-len(suffix))
	return append(append(append([]byte(nil), prefix...), filler...), suffix...)
}

// intFromEnv allows raising the load volume without touching the code:
// the default value must stay runnable in CI, the real measurement is taken
// when the number is needed, not on every push.
func intFromEnv(t *testing.T, name string, fallback int) int {
	t.Helper()
	raw := os.Getenv(name)
	if raw == "" {
		return fallback
	}
	value, err := strconv.Atoi(raw)
	if err != nil || value < 1 {
		t.Fatalf("%s=%q is not a valid number of requests", name, raw)
	}
	return value
}

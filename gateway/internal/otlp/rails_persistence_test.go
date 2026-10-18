package otlp

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"reflect"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bussolabs/closeyourit-ingest-community/gateway/internal/cryptor"
	"github.com/bussolabs/closeyourit-ingest-community/gateway/internal/delivery"
	"github.com/bussolabs/closeyourit-ingest-community/gateway/internal/envelope"
	"github.com/bussolabs/closeyourit-ingest-community/gateway/internal/queue"
	"go.opentelemetry.io/collector/pdata/pcommon"
	"go.opentelemetry.io/collector/pdata/ptrace/ptraceotlp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/trace"
)

type railsTraceConfiguration struct {
	Endpoint         string `json:"endpoint"`
	ProjectID        string `json:"project_id"`
	OtherProjectID   string `json:"other_project_id"`
	IngestToken      string `json:"ingest_token"`
	OtherIngestToken string `json:"other_ingest_token"`
	ReadToken        string `json:"read_token"`
	OtherReadToken   string `json:"other_read_token"`
	PublicKey        string `json:"public_key"`
	SentryProjectID  string `json:"sentry_project_id"`
	BackendSHA       string `json:"backend_sha"`
}

// This observer delegates the real JetStream delivery unchanged. It retains only
// in-memory telemetry for assertions; no credential or payload is logged.
type observedTraceConsumer struct {
	queue.Consumer
	cipher   *cryptor.Cryptor
	observed chan envelope.Request
	failures chan string
}

func (c *observedTraceConsumer) Next(ctx context.Context) (*queue.Delivery, error) {
	message, err := c.Consumer.Next(ctx)
	if err != nil {
		return nil, err
	}
	plain, err := c.cipher.Decrypt(message.Ciphertext, []byte(message.Kind))
	if err != nil {
		c.failures <- "Durable message did not decrypt"
		return message, nil
	}
	request, err := envelope.Decode(plain)
	if err != nil || bytes.Equal(plain, message.Ciphertext) || bytes.Contains(message.Ciphertext, []byte("Bearer ")) {
		c.failures <- "Durable envelope encryption or decoding failed"
		return message, nil
	}
	select {
	case c.observed <- request:
	case <-ctx.Done():
	}
	return message, nil
}

type traceDeliveryObservation struct {
	mu         sync.Mutex
	delivered  int
	partial    int
	rejected   int64
	failures   int
	upstreamOK int
}

func (r *traceDeliveryObservation) RecordUpstream(_, _, status string, _ time.Duration) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if status == "200" {
		r.upstreamOK++
	}
}
func (r *traceDeliveryObservation) RecordRetryAfter(string, time.Duration) {}
func (r *traceDeliveryObservation) SetDeliveryWorkers(int)                 {}
func (r *traceDeliveryObservation) AddBusyDeliveryWorkers(int)             {}
func (r *traceDeliveryObservation) RecordDeliveryFailure(reason string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if reason != "otlp_partial_rejection" {
		r.failures++
	}
}
func (r *traceDeliveryObservation) RecordDelivery(_, outcome string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	switch outcome {
	case "delivered":
		r.delivered++
	case "partial_success":
		r.partial++
	default:
		r.failures++
	}
}
func (r *traceDeliveryObservation) RecordOTLPDeliveryRejected(_ string, count int64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.rejected += count
}
func (r *traceDeliveryObservation) counts() (int, int, int64, int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.delivered, r.partial, r.rejected, r.failures
}

// The callback sees real SDK spans before the synchronous exporter runs. It does
// not change SDK data, serialization or transport behavior.
type sourceTraceObservation struct {
	mu        sync.Mutex
	snapshots []sdktrace.ReadOnlySpan
}

func (r *sourceTraceObservation) OnStart(context.Context, sdktrace.ReadWriteSpan) {}
func (r *sourceTraceObservation) OnEnd(span sdktrace.ReadOnlySpan) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.snapshots = append(r.snapshots, span)
}
func (r *sourceTraceObservation) Shutdown(context.Context) error   { return nil }
func (r *sourceTraceObservation) ForceFlush(context.Context) error { return nil }

func TestRailsOfficialSDKTracePersistence(t *testing.T) {
	config, endpoint, client := readRailsTraceConfiguration(t)
	if otel.Version() != "1.46.0" {
		t.Fatal("Trace certification requires the pinned official SDK version")
	}
	authorizer := RemoteAuthorizer{Upstream: endpoint, Client: client}
	h := newHarnessWithAuthorizer(t, authorizer)
	observed := &observedTraceConsumer{Consumer: h.store, cipher: h.cipher, observed: make(chan envelope.Request, 32), failures: make(chan string, 32)}
	recorder := &traceDeliveryObservation{}
	worker := delivery.NewWorker(observed, h.store, h.cipher, endpoint, client, slog.New(slog.NewTextHandler(io.Discard, nil)))
	worker.SetRecorder(recorder)
	workerContext, stopWorker := context.WithCancel(context.Background())
	workerDone := make(chan error, 1)
	go func() { workerDone <- worker.Run(workerContext, 1) }()
	t.Cleanup(func() {
		stopWorker()
		select {
		case err := <-workerDone:
			if err != nil && !errors.Is(err, context.Canceled) {
				t.Error("Real delivery worker did not stop cleanly")
			}
		case <-time.After(5 * time.Second):
			t.Error("Real delivery worker shutdown timed out")
		}
	})

	code, _ := h.post(t, "traces", []byte(`{}`), "application/json", "", "Bearer "+config.IngestToken)
	if code != 200 {
		t.Fatal("Empty OTLP export was not accepted")
	}
	assertTraceQueueEmpty(t, h)
	for _, protocol := range []string{"http", "grpc"} {
		t.Run(protocol, func(t *testing.T) {
			verifyRailsTraceProtocol(t, config, client, h, observed, recorder, protocol)
		})
	}
	select {
	case failure := <-observed.failures:
		t.Fatal(failure)
	default:
	}
	assertTraceQueueEmpty(t, h)
	delivered, partial, rejected, failures := recorder.counts()
	if delivered < 8 || partial != 2 || rejected != 2 || failures != 0 {
		t.Fatalf("Delivery observation mismatch: delivered=%d partial=%d rejected=%d failures=%d", delivered, partial, rejected, failures)
	}
	t.Logf("Verified official Go SDK 1.46.0 HTTP+gRPC gzip -> encrypted JetStream -> real delivery -> private Rails readback; zero/one/many, two services, child before parent, duplicate/conflict, project isolation, privacy and nanosecond precision; backend=%s", config.BackendSHA)
	t.Logf("Observed runtime=%s os=%s architecture=%s", runtime.Version(), runtime.GOOS, runtime.GOARCH)
}

func readRailsTraceConfiguration(t *testing.T) (railsTraceConfiguration, *url.URL, *http.Client) {
	t.Helper()
	if os.Getenv("CYI_OTLP_RAILS_TEST") != "1" {
		t.Skip("Requires an isolated certification Rails backend and private stdin configuration")
	}
	info, err := os.Stdin.Stat()
	if err != nil || info.Mode()&os.ModeNamedPipe == 0 {
		t.Fatal("Integration configuration requires an anonymous stdin pipe")
	}
	var config railsTraceConfiguration
	body, err := io.ReadAll(io.LimitReader(os.Stdin, 16*1024+1))
	if err != nil || len(body) > 16*1024 || json.Unmarshal(body, &config) != nil {
		t.Fatal("Invalid private trace integration configuration")
	}
	endpoint, err := url.Parse(config.Endpoint)
	if err != nil || endpoint.Scheme != "http" || endpoint.Hostname() != "127.0.0.1" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" || (endpoint.Path != "" && endpoint.Path != "/") {
		t.Fatal("Integration backend must be a plain loopback HTTP endpoint")
	}
	if !identifier.MatchString(config.ProjectID) || !identifier.MatchString(config.OtherProjectID) || config.IngestToken == "" || config.OtherIngestToken == "" || config.ReadToken == "" || config.OtherReadToken == "" || config.PublicKey == "" || len(config.BackendSHA) != 40 {
		t.Fatal("Private trace integration configuration is incomplete")
	}
	client := &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	code, version := railsTraceRequest(t, client, config.Endpoint, "GET", "/version", "", nil)
	if code != 200 || version["sha"] != config.BackendSHA {
		t.Fatal("Observed backend identity does not match the expected checkout")
	}
	return config, endpoint, client
}

func railsTraceRequest(t *testing.T, client *http.Client, endpoint, method, path, token string, body []byte) (int, map[string]any) {
	t.Helper()
	request, err := http.NewRequest(method, endpoint+path, bytes.NewReader(body))
	if err != nil {
		t.Fatal("Cannot construct private trace request")
	}
	request.Header.Set("Content-Type", "application/json")
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal("Private trace HTTP request failed")
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, 1024*1024+1))
	if err != nil || len(data) > 1024*1024 {
		t.Fatal("Private trace response exceeded its read budget")
	}
	if response.StatusCode == http.StatusNotFound && len(data) == 0 {
		return response.StatusCode, nil
	}
	var document map[string]any
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	if decoder.Decode(&document) != nil {
		t.Fatalf("Private trace response was not JSON (HTTP %d)", response.StatusCode)
	}
	return response.StatusCode, document
}

func assertTraceQueueEmpty(t *testing.T, h *harness) {
	t.Helper()
	waitTraceCondition(t, "Durable queues did not drain", func() bool {
		stats, err := h.store.Stats(context.Background())
		if err != nil {
			return false
		}
		for _, stream := range stats.Streams {
			if stream.Messages != 0 {
				return false
			}
		}
		return true
	})
}

func waitTraceCondition(t *testing.T, message string, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal(message)
}

func nextObservedTrace(t *testing.T, observed *observedTraceConsumer) envelope.Request {
	t.Helper()
	select {
	case request := <-observed.observed:
		return request
	case failure := <-observed.failures:
		t.Fatal(failure)
	case <-time.After(10 * time.Second):
		t.Fatal("SDK export was not observed in the encrypted queue")
	}
	return envelope.Request{}
}

func officialTraceProvider(t *testing.T, h *harness, config railsTraceConfiguration, protocol, service string, source *sourceTraceObservation) *sdktrace.TracerProvider {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	headers := map[string]string{"Authorization": "Bearer " + config.IngestToken, "X-CloseYourIt-Project-Id": config.OtherProjectID}
	var exporter sdktrace.SpanExporter
	var err error
	if protocol == "http" {
		exporter, err = otlptracehttp.New(ctx, otlptracehttp.WithEndpoint(h.receiver.HTTPListener.Addr().String()), otlptracehttp.WithInsecure(), otlptracehttp.WithHeaders(headers), otlptracehttp.WithCompression(otlptracehttp.GzipCompression))
	} else {
		exporter, err = otlptracegrpc.New(ctx, otlptracegrpc.WithEndpoint(h.receiver.GRPCListener.Addr().String()), otlptracegrpc.WithInsecure(), otlptracegrpc.WithHeaders(headers), otlptracegrpc.WithCompressor("gzip"))
	}
	if err != nil {
		t.Fatal("Official trace exporter initialization failed")
	}
	provider := sdktrace.NewTracerProvider(sdktrace.WithResource(resource.NewWithAttributes("https://opentelemetry.io/schemas/1.40.0", attribute.String("service.name", service), attribute.String("deployment.environment.name", "certification"))), sdktrace.WithSpanProcessor(source), sdktrace.WithSyncer(exporter))
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if provider.Shutdown(ctx) != nil {
			t.Error("Official trace SDK shutdown failed")
		}
	})
	return provider
}

func spanRows(t *testing.T, client *http.Client, config railsTraceConfiguration, traceID, token string, expected int) []map[string]any {
	t.Helper()
	var rows []map[string]any
	waitTraceCondition(t, "Authenticated trace span count did not converge", func() bool {
		status, document := railsTraceRequest(t, client, config.Endpoint, "GET", "/api/v1/traces/"+traceID+"/spans", token, nil)
		if status == 404 {
			rows = nil
			return expected == 0
		}
		if status != 200 {
			t.Fatalf("Authenticated trace read failed (HTTP %d)", status)
		}
		data, ok := document["data"].([]any)
		if !ok {
			t.Fatal("Trace readback did not contain an array")
		}
		rows = nil
		for _, value := range data {
			row, ok := value.(map[string]any)
			if !ok {
				t.Fatal("Trace readback contained a non-object span")
			}
			rows = append(rows, row)
		}
		return len(rows) == expected
	})
	return rows
}

func verifyRailsTraceProtocol(t *testing.T, config railsTraceConfiguration, client *http.Client, h *harness, observed *observedTraceConsumer, recorder *traceDeliveryObservation, protocol string) {
	source := &sourceTraceObservation{}
	parentProvider := officialTraceProvider(t, h, config, protocol, "certification-edge", source)
	childProvider := officialTraceProvider(t, h, config, protocol, "certification-worker", source)
	start := time.Now().UTC().Truncate(time.Second).Add(123456789 * time.Nanosecond)
	parentContext, parent := parentProvider.Tracer("certification-parent", trace.WithInstrumentationVersion("1.2.3"), trace.WithSchemaURL("https://opentelemetry.io/schemas/1.40.0")).Start(context.Background(), "parent-operation", trace.WithTimestamp(start), trace.WithSpanKind(trace.SpanKindServer))
	traceID := parent.SpanContext().TraceID().String()
	spanRows(t, client, config, traceID, config.ReadToken, 0)
	carrier := propagation.MapCarrier{}
	propagator := propagation.TraceContext{}
	propagator.Inject(parentContext, carrier)
	childContext := propagator.Extract(context.Background(), carrier)
	if !trace.SpanContextFromContext(childContext).IsRemote() {
		t.Fatal("Official W3C propagator did not produce a remote parent")
	}
	_, child := childProvider.Tracer("certification-child", trace.WithInstrumentationVersion("4.5.6"), trace.WithInstrumentationAttributes(attribute.String("scope.marker", "official-sdk"))).Start(childContext, "child-operation", trace.WithTimestamp(start.Add(time.Nanosecond)), trace.WithSpanKind(trace.SpanKindClient), trace.WithLinks(trace.Link{SpanContext: parent.SpanContext(), Attributes: []attribute.KeyValue{attribute.String("link.marker", "linked-parent")}}))
	child.SetAttributes(attribute.String("debug.note", "request failed: "+config.IngestToken), attribute.String("user.email", "trace-private@example.test"), attribute.Int64("counter.large", 9007199254740993), attribute.StringSlice("labels", []string{"one", "two"}))
	child.AddEvent("work-started", trace.WithTimestamp(start.Add(2*time.Nanosecond)), trace.WithAttributes(attribute.String("event.marker", "original-event")))
	child.SetStatus(codes.Error, "operation failed")
	child.End(trace.WithTimestamp(start.Add(100000007 * time.Nanosecond)))
	childEnvelope := nextObservedTrace(t, observed)
	if childEnvelope.Path != "/api/v1/projects/"+config.ProjectID+"/otlp/traces" || bytes.Contains(childEnvelope.Body, []byte(config.IngestToken)) || bytes.Contains(childEnvelope.Body, []byte("trace-private@example.test")) {
		t.Fatal("Routing or pre-encryption privacy assertions failed")
	}
	verifyQueuedSDKChild(t, childEnvelope.Body, start, parent.SpanContext())
	childRows := spanRows(t, client, config, traceID, config.ReadToken, 1)
	if childRows[0]["parent_span_id"] != parent.SpanContext().SpanID().String() {
		t.Fatal("Child arriving before its parent lost the parent span identity")
	}
	verifyTraceTopology(t, client, config, traceID, false, "1", "incomplete", "1")
	parent.End(trace.WithTimestamp(start.Add(200000009 * time.Nanosecond)))
	parentEnvelope := nextObservedTrace(t, observed)
	rows := spanRows(t, client, config, traceID, config.ReadToken, 2)
	verifyTraceTopology(t, client, config, traceID, true, "0", "unknown", "2")
	verifyPersistedTraceFields(t, rows, childEnvelope.Body, parentEnvelope.Body, config)
	source.mu.Lock()
	privatePresent := len(source.snapshots) == 2
	childObserved := false
	for _, span := range source.snapshots {
		if span.Name() != "child-operation" {
			continue
		}
		childObserved = true
		found := false
		for _, attr := range span.Attributes() {
			if attr.Key == "debug.note" && attr.Value.AsString() == "request failed: "+config.IngestToken {
				found = true
			}
		}
		privatePresent = privatePresent && found
	}
	source.mu.Unlock()
	if !privatePresent || !childObserved {
		t.Fatal("Privacy assertion lacked an original SDK value before scrubbing")
	}
	verifyTraceReplaysAndIsolation(t, config, client, h, observed, recorder, traceID, childEnvelope)
	t.Logf("Trace assertions passed: protocol=%s gzip=true service_identities=2 sdk_spans=2 derived_protocol_spans=1 child_first=true exact_nanoseconds=true source_privacy_present=true durable_and_readback_privacy_absent=true", protocol)
}

func verifyTraceTopology(t *testing.T, client *http.Client, config railsTraceConfiguration, traceID string, root bool, missing, completeness, retained string) {
	t.Helper()
	status, document := railsTraceRequest(t, client, config.Endpoint, "GET", "/api/v1/traces/"+traceID, config.ReadToken, nil)
	data, _ := document["data"].(map[string]any)
	topology, _ := data["topology"].(map[string]any)
	if status != 200 || data["retained_spans_count"] != json.Number(retained) || topology["root_present"] != root || topology["missing_parent_count"] != json.Number(missing) || topology["completeness"] != completeness {
		t.Fatal("Trace topology did not reflect the observed out-of-order parent relationship")
	}
}

func verifyQueuedSDKChild(t *testing.T, body []byte, start time.Time, parent trace.SpanContext) {
	t.Helper()
	export := ptraceotlp.NewExportRequest()
	if export.UnmarshalJSON(body) != nil || export.Traces().SpanCount() != 1 {
		t.Fatal("Original SDK child export could not be decoded")
	}
	resourceSpans := export.Traces().ResourceSpans().At(0)
	scopeSpans := resourceSpans.ScopeSpans().At(0)
	span := scopeSpans.Spans().At(0)
	service, _ := resourceSpans.Resource().Attributes().Get("service.name")
	scopeMarker, _ := scopeSpans.Scope().Attributes().Get("scope.marker")
	counter, _ := span.Attributes().Get("counter.large")
	if service.Str() != "certification-worker" || resourceSpans.SchemaUrl() != "https://opentelemetry.io/schemas/1.40.0" || scopeSpans.Scope().Name() != "certification-child" || scopeSpans.Scope().Version() != "4.5.6" || scopeMarker.Str() != "official-sdk" {
		t.Fatal("Resource or instrumentation scope changed before durable admission")
	}
	if span.TraceID().String() != parent.TraceID().String() || span.ParentSpanID().String() != parent.SpanID().String() || uint64(span.StartTimestamp()) != uint64(start.UnixNano()+1) || uint64(span.EndTimestamp()) != uint64(start.UnixNano()+100000007) || counter.Int() != 9007199254740993 {
		t.Fatal("SDK identity or integer precision changed before durable admission")
	}
	if span.Events().Len() != 1 || span.Events().At(0).Name() != "work-started" || uint64(span.Events().At(0).Timestamp()) != uint64(start.UnixNano()+2) || span.Links().Len() != 1 || span.Links().At(0).SpanID().String() != parent.SpanID().String() || span.Links().At(0).TraceID().String() != parent.TraceID().String() || span.Status().Code().String() != "Error" || span.Status().Message() != "operation failed" {
		t.Fatal("SDK event, link or status changed before durable admission")
	}
}

func verifyPersistedTraceFields(t *testing.T, rows []map[string]any, childBody, parentBody []byte, config railsTraceConfiguration) {
	t.Helper()
	// The exact read API projection is compared with real normalized SDK exports.
	for _, body := range [][]byte{childBody, parentBody} {
		export := ptraceotlp.NewExportRequest()
		if export.UnmarshalJSON(body) != nil || export.Traces().SpanCount() != 1 {
			t.Fatal("Observed SDK export does not contain one span")
		}
		resourceSpans := export.Traces().ResourceSpans().At(0)
		scopeSpans := resourceSpans.ScopeSpans().At(0)
		span := scopeSpans.Spans().At(0)
		var row map[string]any
		for _, item := range rows {
			if item["span_id"] == span.SpanID().String() {
				row = item
			}
		}
		if row == nil || row["trace_id"] != span.TraceID().String() || row["name"] != span.Name() || row["start_time_unix_nano"] != strconv.FormatUint(uint64(span.StartTimestamp()), 10) || row["end_time_unix_nano"] != strconv.FormatUint(uint64(span.EndTimestamp()), 10) {
			t.Fatal("Persisted trace identity, name or nanosecond timestamps changed")
		}
		if row["api_schema_version"] != json.Number("1") || row["kind"] != json.Number(strconv.Itoa(int(span.Kind()))) || row["status_code"] != json.Number(strconv.Itoa(int(span.Status().Code()))) {
			t.Fatal("Trace API schema, span kind or status projection changed")
		}
		readback, err := json.Marshal(map[string]any{"resourceSpans": []any{map[string]any{
			"resource": row["resource"], "schemaUrl": row["resource_schema_url"], "scopeSpans": []any{map[string]any{
				"scope": row["instrumentation_scope"], "schemaUrl": row["scope_schema_url"], "spans": []any{row["payload"]},
			}},
		}}})
		if err != nil || !reflect.DeepEqual(canonicalTraceJSON(t, readback), canonicalTraceJSON(t, body)) {
			t.Fatal("Resource, scope, event, link, status or span attributes changed during persistence")
		}
		if row["resource_schema_url"] != resourceSpans.SchemaUrl() || row["scope_schema_url"] != scopeSpans.SchemaUrl() {
			t.Fatal("OTLP schema URL identity changed during persistence")
		}
	}
	serialized, _ := json.Marshal(rows)
	if bytes.Contains(serialized, []byte(config.IngestToken)) || bytes.Contains(serialized, []byte("trace-private@example.test")) {
		t.Fatal("Private trace readback contains an original privacy sentinel")
	}
}

// Official pdata decoding gives omitted fields and explicit OTLP defaults the
// same meaning. Attribute key order is immaterial; event/link order is retained.
func canonicalTraceJSON(t *testing.T, body []byte) any {
	t.Helper()
	export := ptraceotlp.NewExportRequest()
	if export.UnmarshalJSON(body) != nil {
		t.Fatal("Stored trace is not a valid OTLP projection")
	}
	canonical, err := export.MarshalJSON()
	if err != nil {
		t.Fatal("Cannot canonicalize the OTLP projection")
	}
	var result any
	decoder := json.NewDecoder(bytes.NewReader(canonical))
	decoder.UseNumber()
	if decoder.Decode(&result) != nil {
		t.Fatal("Cannot inspect canonical OTLP JSON")
	}
	sortTraceAttributes(result)
	return result
}

func sortTraceAttributes(value any) {
	switch current := value.(type) {
	case map[string]any:
		for key, child := range current {
			if key == "stringValue" && child == "[FILTERED]" {
				// Both components use explicit redaction markers with different casing.
				current[key] = "[Filtered]"
			}
			if key == "attributes" {
				if attributes, ok := child.([]any); ok {
					sort.Slice(attributes, func(i, j int) bool {
						return attributes[i].(map[string]any)["key"].(string) < attributes[j].(map[string]any)["key"].(string)
					})
				}
			}
			sortTraceAttributes(child)
		}
	case []any:
		for _, child := range current {
			sortTraceAttributes(child)
		}
	}
}

func verifyTraceReplaysAndIsolation(t *testing.T, config railsTraceConfiguration, client *http.Client, h *harness, observed *observedTraceConsumer, recorder *traceDeliveryObservation, traceID string, child envelope.Request) {
	post := func(body []byte, token string, rejected int64) envelope.Request {
		code, response := h.post(t, "traces", body, "application/json", "", "Bearer "+token)
		result := ptraceotlp.NewExportResponse()
		if code != 200 || result.UnmarshalJSON(response) != nil || result.PartialSuccess().RejectedSpans() != rejected {
			t.Fatalf("Protocol replay admission failed (HTTP %d)", code)
		}
		request := nextObservedTrace(t, observed)
		assertTraceQueueEmpty(t, h)
		return request
	}
	post(child.Body, config.IngestToken, 0)
	spanRows(t, client, config, traceID, config.ReadToken, 2)
	conflict := ptraceotlp.NewExportRequest()
	if conflict.UnmarshalJSON(child.Body) != nil {
		t.Fatal("Cannot decode the SDK event for the explicit conflict protocol case")
	}
	spans := conflict.Traces().ResourceSpans().At(0).ScopeSpans().At(0).Spans()
	original := spans.At(0)
	accepted := spans.AppendEmpty()
	original.CopyTo(accepted)
	var freshID pcommon.SpanID
	if _, err := rand.Read(freshID[:]); err != nil {
		t.Fatal("Cannot allocate an independent protocol test identity")
	}
	accepted.SetSpanID(freshID)
	accepted.SetName("protocol-derived-span")
	privateBytes := []byte("byte note: " + config.IngestToken + " private@example.test")
	accepted.Attributes().PutEmptyBytes("byte.note").FromRaw(privateBytes)
	accepted.Attributes().PutEmptyBytes("safe.bytes").FromRaw([]byte("safe UTF-8 λ"))
	accepted.Attributes().PutStr("card_number", "private-card-value")
	opaque := spans.AppendEmpty()
	accepted.CopyTo(opaque)
	opaqueID := freshID
	opaqueID[0] ^= 1
	opaque.SetSpanID(opaqueID)
	opaque.Attributes().PutEmptyBytes("opaque.note").FromRaw([]byte{0xff, 0xfe, 0xfd})
	original.SetName("conflicting-replay")
	conflictBody, _ := conflict.MarshalJSON()
	_, _, rejectedBefore, _ := recorder.counts()
	queued := post(conflictBody, config.IngestToken, 1)
	for _, forbidden := range []string{config.IngestToken, "private@example.test", "private-card-value", base64.StdEncoding.EncodeToString(privateBytes), base64.StdEncoding.EncodeToString([]byte{0xff, 0xfe, 0xfd})} {
		if bytes.Contains(queued.Body, []byte(forbidden)) {
			t.Fatal("Privacy sentinel or opaque byte payload reached encrypted durable admission")
		}
	}
	queuedExport := ptraceotlp.NewExportRequest()
	if queuedExport.UnmarshalJSON(queued.Body) != nil || queuedExport.Traces().SpanCount() != 2 {
		t.Fatal("Opaque byte rejection changed independently admissible trace records")
	}
	var queuedDocument map[string]any
	if json.Unmarshal(queued.Body, &queuedDocument) != nil {
		t.Fatal("Cannot inspect queued protocol byte values")
	}
	queuedSpans := queuedDocument["resourceSpans"].([]any)[0].(map[string]any)["scopeSpans"].([]any)[0].(map[string]any)["spans"].([]any)
	byteRecordObserved := false
	for _, record := range queuedSpans {
		if record.(map[string]any)["name"] == "protocol-derived-span" {
			verifyDecodedTraceBytes(t, record, config.IngestToken)
			byteRecordObserved = true
		}
	}
	if !byteRecordObserved {
		t.Fatal("Derived byte-bearing span was missing from durable admission")
	}
	_, _, rejectedAfter, _ := recorder.counts()
	if rejectedAfter != rejectedBefore+1 {
		t.Fatal("Conflicting duplicate was not diagnosed by real delivery")
	}
	rows := spanRows(t, client, config, traceID, config.ReadToken, 3)
	freshPersisted := false
	for _, row := range rows {
		if row["name"] == "conflicting-replay" {
			t.Fatal("Conflicting replay overwrote the original span")
		}
		if row["span_id"] == freshID.String() && row["name"] == "protocol-derived-span" {
			freshPersisted = true
			verifyDecodedTraceBytes(t, row["payload"], config.IngestToken)
			payload, _ := json.Marshal(row["payload"])
			if bytes.Contains(payload, []byte(base64.StdEncoding.EncodeToString(privateBytes))) || !bytes.Contains(payload, []byte(base64.StdEncoding.EncodeToString([]byte("safe UTF-8 λ")))) {
				t.Fatal("Byte privacy or non-sensitive byte preservation failed at readback")
			}
		}
	}
	if !freshPersisted {
		t.Fatal("Partial rejection lost the independently accepted new span")
	}
	spanRows(t, client, config, traceID, config.OtherReadToken, 0)
	for _, token := range []string{"", config.PublicKey, config.IngestToken} {
		status, _ := railsTraceRequest(t, client, config.Endpoint, "GET", "/api/v1/traces/"+traceID+"/spans", token, nil)
		if status != 401 && status != 403 {
			t.Fatal("Private traces were accessible without read scope")
		}
	}
	status, _ := railsTraceRequest(t, client, config.Endpoint, "POST", "/api/v1/projects/"+config.OtherProjectID+"/otlp/traces", config.IngestToken, child.Body)
	if status != 404 {
		t.Fatal("Project credential was accepted for another project ingestion path")
	}
	post(child.Body, config.OtherIngestToken, 0)
	otherRows := spanRows(t, client, config, traceID, config.OtherReadToken, 1)
	if otherRows[0]["span_id"] != childSpanID(t, child.Body) {
		t.Fatal("Identical span IDs could not be isolated by project")
	}
	spanRows(t, client, config, traceID, config.ReadToken, 3)
}

func verifyDecodedTraceBytes(t *testing.T, payload any, credential string) {
	t.Helper()
	span, ok := payload.(map[string]any)
	if !ok {
		t.Fatal("Byte privacy proof requires an observed span payload")
	}
	attributes, ok := span["attributes"].([]any)
	if !ok {
		t.Fatal("Byte privacy proof requires original typed attributes")
	}
	decoded := map[string][]byte{}
	for _, attribute := range attributes {
		item, _ := attribute.(map[string]any)
		key, _ := item["key"].(string)
		if key != "byte.note" && key != "safe.bytes" {
			continue
		}
		value, _ := item["value"].(map[string]any)
		encoded, ok := value["bytesValue"].(string)
		bytes, err := base64.StdEncoding.DecodeString(encoded)
		if !ok || err != nil {
			t.Fatal("Observed byte attribute lost its OTLP bytes type")
		}
		decoded[key] = bytes
	}
	note := string(decoded["byte.note"])
	if !strings.HasPrefix(note, "byte note: ") || strings.Contains(note, credential) || strings.Contains(note, "private@example.test") || string(decoded["safe.bytes"]) != "safe UTF-8 λ" {
		t.Fatal("Decoded bytes leaked a credential or email, or lost non-sensitive content")
	}
}

func childSpanID(t *testing.T, body []byte) string {
	t.Helper()
	export := ptraceotlp.NewExportRequest()
	if export.UnmarshalJSON(body) != nil {
		t.Fatal("Cannot inspect original SDK span identity")
	}
	return export.Traces().ResourceSpans().At(0).ScopeSpans().At(0).Spans().At(0).SpanID().String()
}

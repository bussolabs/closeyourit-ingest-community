package otlp

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"reflect"
	"runtime"
	"sort"
	"strconv"
	"testing"
	"time"

	"github.com/bussolabs/closeyourit-ingest-community/gateway/internal/delivery"
	"github.com/bussolabs/closeyourit-ingest-community/gateway/internal/envelope"
	"go.opentelemetry.io/collector/pdata/plog/plogotlp"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploggrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"
	logapi "go.opentelemetry.io/otel/log"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	"go.opentelemetry.io/otel/sdk/resource"
)

type logPersistenceProof struct {
	t        *testing.T
	config   railsTraceConfiguration
	client   *http.Client
	h        *harness
	observed *observedTraceConsumer
	recorder *traceDeliveryObservation
}

func TestRailsOfficialSDKLogPersistence(t *testing.T) {
	config, endpoint, client := readRailsTraceConfiguration(t)
	h := newHarnessWithAuthorizer(t, RemoteAuthorizer{Upstream: endpoint, Client: client})
	p := &logPersistenceProof{t: t, config: config, client: client, h: h,
		observed: &observedTraceConsumer{Consumer: h.store, cipher: h.cipher, observed: make(chan envelope.Request, 64), failures: make(chan string, 64)}, recorder: &traceDeliveryObservation{}}
	worker := delivery.NewWorker(p.observed, h.store, h.cipher, endpoint, client, slog.New(slog.NewTextHandler(io.Discard, nil)))
	worker.SetRecorder(p.recorder)
	ctx, cancel := context.WithCancel(context.Background())
	finished := make(chan error, 1)
	go func() { finished <- worker.Run(ctx, 1) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-finished:
			if err != nil && !errors.Is(err, context.Canceled) {
				t.Error("Real log delivery worker did not stop cleanly")
			}
		case <-time.After(5 * time.Second):
			t.Error("Real log delivery worker shutdown timed out")
		}
	})
	code, _ := h.post(t, "logs", []byte(`{}`), "application/json", "", "Bearer "+config.IngestToken)
	if code != 200 || len(p.rows("/api/v1/log_entries", config.ReadToken)) != 0 {
		t.Fatal("Empty export created a log or was rejected")
	}
	assertTraceQueueEmpty(t, h)
	for _, protocol := range []string{"http", "grpc"} {
		t.Run(protocol, func(t *testing.T) { child := *p; child.t = t; child.verifyProtocol(protocol) })
	}
	assertTraceQueueEmpty(t, h)
	select {
	case failure := <-p.observed.failures:
		t.Fatal(failure)
	default:
	}
	_, _, _, failures := p.recorder.counts()
	if failures != 0 {
		t.Fatal("Log delivery recorded an unexpected failure")
	}
	t.Logf("Verified official Go log SDK 0.22.0 HTTP+gRPC gzip, encrypted JetStream, real delivery, private typed logs and explicit error correlation; backend=%s runtime=%s os=%s architecture=%s", config.BackendSHA, runtime.Version(), runtime.GOOS, runtime.GOARCH)
}

func (p *logPersistenceProof) rows(path, token string) []map[string]any {
	p.t.Helper()
	var rows []map[string]any
	separator := "?"
	for _, c := range path {
		if c == '?' {
			separator = "&"
			break
		}
	}
	for page := 1; page <= 30; page++ {
		code, document := railsTraceRequest(p.t, p.client, p.config.Endpoint, "GET", path+separator+"per=1&page="+strconv.Itoa(page), token, nil)
		if code != 200 {
			p.t.Fatalf("Private log/correlation read failed (HTTP %d)", code)
		}
		data, ok := document["data"].([]any)
		if !ok {
			p.t.Fatal("Private log/correlation read did not contain an array")
		}
		for _, value := range data {
			row, ok := value.(map[string]any)
			if !ok {
				p.t.Fatal("Private read contained a non-object")
			}
			rows = append(rows, row)
		}
		meta, ok := document["meta"].(map[string]any)
		if !ok {
			p.t.Fatal("Private log/correlation read did not expose pagination")
		}
		if strconv.Itoa(page) == stringNumber(meta["total_pages"]) || len(data) == 0 {
			return rows
		}
	}
	p.t.Fatal("Private read exceeded its pagination budget")
	return nil
}

func (p *logPersistenceProof) logs(traceID string, expected int) []map[string]any {
	var rows []map[string]any
	waitTraceCondition(p.t, "Persisted log count did not converge", func() bool {
		rows = p.rows("/api/v1/log_entries?trace_id="+traceID, p.config.ReadToken)
		return len(rows) == expected
	})
	encoded, _ := json.Marshal(rows)
	if bytes.Contains(encoded, []byte(p.config.IngestToken)) {
		p.t.Fatal("Private logs retain the source credential")
	}
	return rows
}

func (p *logPersistenceProof) provider(protocol string) *sdklog.LoggerProvider {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	headers := map[string]string{"Authorization": "Bearer " + p.config.IngestToken, "X-CloseYourIt-Project-Id": p.config.OtherProjectID}
	var exporter sdklog.Exporter
	var err error
	if protocol == "http" {
		exporter, err = otlploghttp.New(ctx, otlploghttp.WithEndpoint(p.h.receiver.HTTPListener.Addr().String()), otlploghttp.WithInsecure(), otlploghttp.WithHeaders(headers), otlploghttp.WithCompression(otlploghttp.GzipCompression))
	} else {
		exporter, err = otlploggrpc.New(ctx, otlploggrpc.WithEndpoint(p.h.receiver.GRPCListener.Addr().String()), otlploggrpc.WithInsecure(), otlploggrpc.WithHeaders(headers), otlploggrpc.WithCompressor("gzip"))
	}
	if err != nil {
		p.t.Fatal("Official log exporter initialization failed")
	}
	provider := sdklog.NewLoggerProvider(sdklog.WithProcessor(sdklog.NewSimpleProcessor(exporter)), sdklog.WithResource(resource.NewWithAttributes("https://opentelemetry.io/schemas/1.40.0", attribute.String("service.name", "certification-logs"), attribute.String("service.version", "1.2.3"), attribute.String("deployment.environment.name", "certification"), attribute.String("debug.note", "original: "+p.config.IngestToken))))
	p.t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if provider.Shutdown(ctx) != nil {
			p.t.Error("Official log SDK shutdown failed")
		}
	})
	return provider
}

func (p *logPersistenceProof) emit(logger logapi.Logger, ctx context.Context, record logapi.Record) envelope.Request {
	logger.Emit(ctx, record)
	request := nextObservedTrace(p.t, p.observed)
	if request.Path != "/api/v1/projects/"+p.config.ProjectID+"/otlp/logs" || bytes.Contains(request.Body, []byte(p.config.IngestToken)) {
		p.t.Fatal("Queued SDK log was misrouted or retained a credential")
	}
	return request
}

func (p *logPersistenceProof) postFixture(request plogotlp.ExportRequest, token string, rejected int64) envelope.Request {
	body, err := request.MarshalJSON()
	if err != nil {
		p.t.Fatal("Cannot encode derived log case")
	}
	code, response := p.h.post(p.t, "logs", body, "application/json", "", "Bearer "+token)
	result := plogotlp.NewExportResponse()
	if code != 200 || result.UnmarshalJSON(response) != nil || result.PartialSuccess().RejectedLogRecords() != rejected {
		p.t.Fatal("Derived log admission returned an unexpected result")
	}
	return nextObservedTrace(p.t, p.observed)
}

func (p *logPersistenceProof) fixture(body []byte) plogotlp.ExportRequest {
	request := plogotlp.NewExportRequest()
	if request.UnmarshalJSON(body) != nil {
		p.t.Fatal("Cannot decode observed SDK logs")
	}
	return request
}

func (p *logPersistenceProof) verifyProtocol(protocol string) {
	provider := p.provider(protocol)
	logger := provider.Logger("certification-logs", logapi.WithInstrumentationVersion("1.2.3"), logapi.WithSchemaURL("https://opentelemetry.io/schemas/1.40.0"), logapi.WithInstrumentationAttributes(attribute.String("library.kind", "test")))
	source := &sourceTraceObservation{}
	tracer := officialTraceProvider(p.t, p.h, p.config, protocol, "certification-logs", source).Tracer("certification-correlation")
	ctx, span := tracer.Start(context.Background(), "correlated-operation")
	spanID, traceID := span.SpanContext().SpanID().String(), span.SpanContext().TraceID().String()
	span.End()
	traceRequest := nextObservedTrace(p.t, p.observed)
	if traceRequest.Path != "/api/v1/projects/"+p.config.ProjectID+"/otlp/traces" {
		p.t.Fatal("Official trace did not cross the real queue")
	}
	spanRows(p.t, p.client, p.config, traceID, p.config.ReadToken, 1)
	when := time.Now().UTC().Add(-2 * time.Second).Truncate(time.Second).Add(123456789)
	var record logapi.Record
	record.SetTimestamp(when)
	record.SetObservedTimestamp(when.Add(234567890))
	record.SetSeverity(logapi.SeverityWarn2)
	record.SetSeverityText("custom-warning")
	record.SetBody(attribute.MapValue(attribute.String("message", "structured log"), attribute.Int64("exact", 9007199254740993), attribute.String("credential", p.config.IngestToken)))
	record.AddAttributes(attribute.String("log.record.uid", protocol+"-unique"), attribute.Bool("confirmed", true), attribute.Int64("exact", 9007199254740993))
	sourceHasCredential := false
	for _, item := range record.Body().AsMap() {
		if item.Key == "credential" && item.Value.AsString() == p.config.IngestToken {
			sourceHasCredential = true
		}
	}
	if !sourceHasCredential {
		p.t.Fatal("Source SDK log did not contain the privacy sentinel")
	}
	first := p.emit(logger, ctx, record)
	rows := p.logs(traceID, 1)
	row := rows[0]
	if row["trace_id"] != traceID || row["span_id"] != spanID || stringNumber(row["severity_number"]) != "14" || row["severity_text"] != "custom-warning" || row["event_time_unix_nano"] != strconv.FormatInt(when.UnixNano(), 10) || row["observed_time_unix_nano"] != strconv.FormatInt(when.Add(234567890).UnixNano(), 10) {
		p.t.Fatal("Persisted log lost correlation, severity or exact timestamps")
	}
	p.verifySnapshot(first.Body, row)
	firstReceipt := row["created_at"]
	p.postFixture(p.fixture(first.Body), p.config.IngestToken, 0)
	rows = p.logs(traceID, 1)
	if rows[0]["id"] != row["id"] || rows[0]["created_at"] != firstReceipt {
		p.t.Fatal("Explicit log replay changed identity or first receipt")
	}
	var repeated logapi.Record
	repeated.SetTimestamp(when)
	repeated.SetSeverity(logapi.SeverityError)
	repeated.SetBody(attribute.StringValue("same legitimate line"))
	p.emit(logger, ctx, repeated)
	p.emit(logger, ctx, repeated)
	p.logs(traceID, 3)
	if len(p.rows("/api/v1/traces/"+traceID+"/errors", p.config.ReadToken)) != 0 {
		p.t.Fatal("An error-severity log was incorrectly promoted to a crash")
	}
	p.verifyErrors(logger, ctx, traceID, protocol, when)
	p.verifyBoundaries(first.Body, traceID, row, 5)
	p.t.Logf("Log assertions passed: protocol=%s gzip=true typed_body=true exact_time=true explicit_dedup=true ordinary_logs_preserved=true project_isolation=true", protocol)
}

func (p *logPersistenceProof) verifySnapshot(body []byte, row map[string]any) {
	stored, ok := row["otlp_payload"].(map[string]any)
	if !ok {
		p.t.Fatal("Stored OTLP log snapshot is missing")
	}
	projection := map[string]any{"resourceLogs": []any{map[string]any{
		"resource": stored["resource"], "schemaUrl": stored["resource_schema_url"],
		"scopeLogs": []any{map[string]any{"scope": stored["scope"], "schemaUrl": stored["scope_schema_url"], "logRecords": []any{stored["log_record"]}}},
	}}}
	encoded, err := json.Marshal(projection)
	if err != nil || !reflect.DeepEqual(canonicalLogJSON(p.t, body), canonicalLogJSON(p.t, encoded)) {
		p.t.Fatal("Typed log/resource/scope snapshot changed during persistence")
	}
}

func canonicalLogJSON(t *testing.T, body []byte) any {
	t.Helper()
	request := plogotlp.NewExportRequest()
	if request.UnmarshalJSON(body) != nil {
		t.Fatal("Stored log is not a valid OTLP projection")
	}
	encoded, err := request.MarshalJSON()
	if err != nil {
		t.Fatal("Cannot canonicalize the log projection")
	}
	var value any
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	if decoder.Decode(&value) != nil {
		t.Fatal("Cannot inspect the log projection")
	}
	sortTraceAttributes(value)
	sortLogMaps(value)
	return value
}

func sortLogMaps(value any) {
	switch item := value.(type) {
	case map[string]any:
		if kv, ok := item["kvlistValue"].(map[string]any); ok {
			if values, ok := kv["values"].([]any); ok {
				sort.Slice(values, func(i, j int) bool {
					return values[i].(map[string]any)["key"].(string) < values[j].(map[string]any)["key"].(string)
				})
			}
		}
		for _, child := range item {
			sortLogMaps(child)
		}
	case []any:
		for _, child := range item {
			sortLogMaps(child)
		}
	}
}

func randomLogEventID(t *testing.T) string {
	t.Helper()
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		t.Fatal("Cannot create an isolated event ID")
	}
	return hex.EncodeToString(id[:])
}

func (p *logPersistenceProof) verifyErrors(logger logapi.Logger, ctx context.Context, traceID, protocol string, when time.Time) {
	for index, order := range []string{"sentry-first", "otlp-first"} {
		eventID := randomLogEventID(p.t)
		if order == "sentry-first" {
			p.sentry(eventID, "", when)
			waitTraceCondition(p.t, "Sentry error without trace context was not persisted", func() bool {
				return p.findError(eventID) != nil
			})
		}
		var exception logapi.Record
		exception.SetTimestamp(when)
		exception.SetEventName("exception")
		exception.SetSeverity(logapi.SeverityError)
		exception.SetBody(attribute.StringValue("explicit failure"))
		exception.AddAttributes(attribute.String("exception.type", "CertificationFailure"), attribute.String("exception.message", "explicit failure"), attribute.String("closeyourit.error.event_id", eventID), attribute.String("log.record.uid", protocol+"-"+order))
		p.emit(logger, ctx, exception)
		p.logs(traceID, 4+index)
		p.errors(traceID, index*2+1)
		if order == "otlp-first" {
			p.sentry(eventID, traceID, when)
		}
		// The certification worker has one ingest thread; a following marker observes completion.
		markerID := randomLogEventID(p.t)
		p.sentry(markerID, traceID, when)
		rows := p.errors(traceID, index*2+2)
		found := 0
		markers := 0
		for _, row := range rows {
			if row["event_id"] == eventID {
				found++
			}
			if row["event_id"] == markerID {
				markers++
			}
		}
		if found != 1 || markers != 1 {
			p.t.Fatal("Explicit cross-channel error identity was not deduplicated")
		}
		if order == "sentry-first" {
			original := p.findError(eventID)
			if original == nil || original["trace_id"] != nil {
				p.t.Fatal("Explicit correlation removed or overwrote the original error context")
			}
		}
	}
}

func (p *logPersistenceProof) findError(eventID string) map[string]any {
	for _, group := range p.rows("/api/v1/error_groups", p.config.ReadToken) {
		for _, event := range p.rows("/api/v1/error_groups/"+group["id"].(string)+"/events", p.config.ReadToken) {
			if event["event_id"] == eventID {
				return event
			}
		}
	}
	return nil
}

func (p *logPersistenceProof) errors(traceID string, expected int) []map[string]any {
	var rows []map[string]any
	waitTraceCondition(p.t, "Correlated error count did not converge", func() bool {
		rows = p.rows("/api/v1/traces/"+traceID+"/errors", p.config.ReadToken)
		return len(rows) == expected
	})
	return rows
}

// This is an explicitly derived Sentry protocol case, not a Sentry SDK observation.
func (p *logPersistenceProof) sentry(eventID, traceID string, when time.Time) {
	event := map[string]any{"event_id": eventID, "timestamp": when.Format(time.RFC3339Nano), "level": "error", "platform": "other", "exception": map[string]any{"values": []any{map[string]any{"type": "CertificationFailure", "value": "explicit failure"}}}, "contexts": map[string]any{"trace": map[string]any{"trace_id": traceID}}}
	encoded, _ := json.Marshal(event)
	header, _ := json.Marshal(map[string]any{"event_id": eventID})
	item, _ := json.Marshal(map[string]any{"type": "event", "length": len(encoded)})
	body := bytes.Join([][]byte{header, item, encoded, {}}, []byte("\n"))
	request, err := http.NewRequest("POST", p.config.Endpoint+"/api/"+p.config.SentryProjectID+"/envelope/", bytes.NewReader(body))
	if err != nil {
		p.t.Fatal("Cannot construct derived Sentry envelope")
	}
	request.Header.Set("Content-Type", "application/x-sentry-envelope")
	request.Header.Set("X-Sentry-Auth", "Sentry sentry_version=7, sentry_key="+p.config.PublicKey)
	response, err := p.client.Do(request)
	if err != nil {
		p.t.Fatal("Derived Sentry envelope did not reach Rails")
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(response.Body, 1024*1024))
	if response.StatusCode != 200 {
		p.t.Fatalf("Derived Sentry envelope rejected (HTTP %d)", response.StatusCode)
	}
}

func (p *logPersistenceProof) verifyBoundaries(body []byte, traceID string, original map[string]any, expected int) {
	request := p.fixture(body)
	logs := request.Logs().ResourceLogs().At(0).ScopeLogs().At(0).LogRecords()
	logs.At(0).Body().SetStr("conflicting identity")
	logs.At(0).CopyTo(logs.AppendEmpty())
	logs.At(1).Attributes().PutStr("log.record.uid", randomLogEventID(p.t))
	logs.At(1).Body().SetStr("independent new log")
	_, _, before, _ := p.recorder.counts()
	p.postFixture(request, p.config.IngestToken, 0)
	rows := p.logs(traceID, expected+1)
	waitTraceCondition(p.t, "Log conflict was not diagnosed at real delivery", func() bool { _, _, rejected, _ := p.recorder.counts(); return rejected == before+1 })
	retained := 0
	for _, row := range rows {
		if row["id"] == original["id"] {
			retained++
			if !reflect.DeepEqual(row, original) {
				p.t.Fatal("Conflicting replay overwrote the original log")
			}
		}
	}
	if retained != 1 {
		p.t.Fatal("Conflicting replay removed or duplicated the original log")
	}
	correlated := p.rows("/api/v1/traces/"+traceID+"/logs", p.config.ReadToken)
	if len(correlated) != expected+1 {
		p.t.Fatal("Trace log correlation omitted a persisted record")
	}
	for _, token := range []string{"", p.config.PublicKey, p.config.IngestToken} {
		status, _ := railsTraceRequest(p.t, p.client, p.config.Endpoint, "GET", "/api/v1/log_entries", token, nil)
		if status != 401 && status != 403 {
			p.t.Fatal("Logs were accessible without private read scope")
		}
	}
	for _, suffix := range []string{"logs", "errors"} {
		status, _ := railsTraceRequest(p.t, p.client, p.config.Endpoint, "GET", "/api/v1/traces/"+traceID+"/"+suffix, p.config.OtherReadToken, nil)
		if status != 404 {
			p.t.Fatal("Trace correlation crossed the project boundary")
		}
	}
	status, _ := railsTraceRequest(p.t, p.client, p.config.Endpoint, "POST", "/api/v1/projects/"+p.config.OtherProjectID+"/otlp/logs", p.config.IngestToken, body)
	if status != 404 {
		p.t.Fatal("Log ingest accepted a conflicting project path")
	}
	p.postFixture(p.fixture(body), p.config.OtherIngestToken, 0)
	waitTraceCondition(p.t, "Identical log identity did not persist independently in another project", func() bool { return len(p.rows("/api/v1/log_entries?trace_id="+traceID, p.config.OtherReadToken)) == 1 })
	if len(p.logs(traceID, expected+1)) != expected+1 {
		p.t.Fatal("Other-project log changed the original tenant")
	}
}

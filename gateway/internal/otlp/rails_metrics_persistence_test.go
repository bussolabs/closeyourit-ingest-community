package otlp

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"math"
	"net/http"
	"net/url"
	"reflect"
	"runtime"
	"strconv"
	"testing"
	"time"

	"github.com/bussolabs/closeyourit-ingest-community/gateway/internal/delivery"
	"github.com/bussolabs/closeyourit-ingest-community/gateway/internal/envelope"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/pdata/pmetric/pmetricotlp"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	metricapi "go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"go.opentelemetry.io/otel/sdk/resource"
)

type metricPersistenceProof struct {
	t        *testing.T
	config   railsTraceConfiguration
	client   *http.Client
	h        *harness
	observed *observedTraceConsumer
	recorder *traceDeliveryObservation
}

type officialMetricClient struct {
	provider *sdkmetric.MeterProvider
	reader   *sdkmetric.ManualReader
	exporter sdkmetric.Exporter
	closed   bool
}

func TestRailsOfficialSDKMetricPersistence(t *testing.T) {
	config, endpoint, client := readRailsTraceConfiguration(t)
	if otel.Version() != "1.46.0" {
		t.Fatal("Metric certification requires the pinned official SDK version")
	}
	h := newHarnessWithAuthorizer(t, RemoteAuthorizer{Upstream: endpoint, Client: client})
	proof := &metricPersistenceProof{t: t, config: config, client: client, h: h,
		observed: &observedTraceConsumer{Consumer: h.store, cipher: h.cipher, observed: make(chan envelope.Request, 64), failures: make(chan string, 64)}, recorder: &traceDeliveryObservation{}}
	worker := delivery.NewWorker(proof.observed, h.store, h.cipher, endpoint, client, slog.New(slog.NewTextHandler(io.Discard, nil)))
	worker.SetRecorder(proof.recorder)
	ctx, cancel := context.WithCancel(context.Background())
	finished := make(chan error, 1)
	go func() { finished <- worker.Run(ctx, 1) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-finished:
			if err != nil && !errors.Is(err, context.Canceled) {
				t.Error("Real metric delivery worker did not stop cleanly")
			}
		case <-time.After(5 * time.Second):
			t.Error("Real metric delivery worker shutdown timed out")
		}
	})
	code, _ := h.post(t, "metrics", []byte(`{}`), "application/json", "", "Bearer "+config.IngestToken)
	if code != 200 || len(proof.list("/api/v1/measurement_series", config.ReadToken)) != 0 {
		t.Fatal("Empty metrics export created a series or was rejected")
	}
	assertTraceQueueEmpty(t, h)
	for _, protocol := range []string{"http", "grpc"} {
		t.Run(protocol, func(t *testing.T) {
			childProof := *proof
			childProof.t = t
			childProof.verifyProtocol(protocol)
		})
	}
	assertTraceQueueEmpty(t, h)
	select {
	case failure := <-proof.observed.failures:
		t.Fatal(failure)
	default:
	}
	_, _, _, failures := proof.recorder.counts()
	if failures != 0 {
		t.Fatal("Metric delivery recorded an unexpected failure")
	}
	t.Logf("Verified official Go metric SDK 1.46.0 HTTP+gRPC gzip, encrypted JetStream, real delivery, private persistence and conservative aggregation; backend=%s runtime=%s os=%s architecture=%s", config.BackendSHA, runtime.Version(), runtime.GOOS, runtime.GOARCH)
}

func (p *metricPersistenceProof) officialClient(protocol, prefix string, temporality metricdata.Temporality) *officialMetricClient {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	headers := map[string]string{"Authorization": "Bearer " + p.config.IngestToken, "X-CloseYourIt-Project-Id": p.config.OtherProjectID}
	var exporter sdkmetric.Exporter
	var err error
	if protocol == "http" {
		exporter, err = otlpmetrichttp.New(ctx, otlpmetrichttp.WithEndpoint(p.h.receiver.HTTPListener.Addr().String()), otlpmetrichttp.WithInsecure(), otlpmetrichttp.WithHeaders(headers), otlpmetrichttp.WithCompression(otlpmetrichttp.GzipCompression))
	} else {
		exporter, err = otlpmetricgrpc.New(ctx, otlpmetricgrpc.WithEndpoint(p.h.receiver.GRPCListener.Addr().String()), otlpmetricgrpc.WithInsecure(), otlpmetricgrpc.WithHeaders(headers), otlpmetricgrpc.WithCompressor("gzip"))
	}
	if err != nil {
		p.t.Fatal("Official metric exporter initialization failed")
	}
	reader := sdkmetric.NewManualReader(sdkmetric.WithTemporalitySelector(func(sdkmetric.InstrumentKind) metricdata.Temporality { return temporality }))
	provider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader),
		sdkmetric.WithResource(resource.NewWithAttributes("https://opentelemetry.io/schemas/1.40.0", attribute.String("service.name", "certification-metrics"), attribute.String("debug.note", "original: "+p.config.IngestToken), attribute.String("deployment.environment.name", "certification"))),
		sdkmetric.WithView(sdkmetric.NewView(sdkmetric.Instrument{Name: prefix + ".explicit"}, sdkmetric.Stream{Aggregation: sdkmetric.AggregationExplicitBucketHistogram{Boundaries: []float64{5, 10}}})),
		sdkmetric.WithView(sdkmetric.NewView(sdkmetric.Instrument{Name: prefix + ".exponential"}, sdkmetric.Stream{Aggregation: sdkmetric.AggregationBase2ExponentialHistogram{MaxSize: 160, MaxScale: 20}})))
	result := &officialMetricClient{provider: provider, reader: reader, exporter: exporter}
	p.t.Cleanup(func() { p.closeClient(result) })
	return result
}

func (p *metricPersistenceProof) closeClient(client *officialMetricClient) {
	if client.closed {
		return
	}
	client.closed = true
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	providerErr := client.provider.Shutdown(ctx)
	exporterErr := client.exporter.Shutdown(ctx)
	if providerErr != nil || exporterErr != nil {
		p.t.Error("Official metric SDK shutdown failed")
	}
}

func (p *metricPersistenceProof) collect(client *officialMetricClient) envelope.Request {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	var metrics metricdata.ResourceMetrics
	if client.reader.Collect(ctx, &metrics) != nil {
		p.t.Fatal("Official SDK metric collection failed")
	}
	private := false
	for _, item := range metrics.Resource.Attributes() {
		private = private || (item.Key == "debug.note" && item.Value.AsString() == "original: "+p.config.IngestToken)
	}
	if !private {
		p.t.Fatal("Privacy proof lacked an original SDK value before export")
	}
	if client.exporter.Export(ctx, &metrics) != nil {
		p.t.Fatal("Official SDK metric export failed")
	}
	request := nextObservedTrace(p.t, p.observed)
	if request.Path != "/api/v1/projects/"+p.config.ProjectID+"/otlp/metrics" || bytes.Contains(request.Body, []byte(p.config.IngestToken)) {
		p.t.Fatal("Metric routing or pre-encryption privacy failed")
	}
	assertTraceQueueEmpty(p.t, p.h)
	return request
}

func (p *metricPersistenceProof) list(path, token string) []map[string]any {
	var records []map[string]any
	parsed, err := url.Parse(path)
	if err != nil {
		p.t.Fatal("Invalid metric read path")
	}
	for page := 1; page <= 100; page++ {
		query := parsed.Query()
		query.Set("page", strconv.Itoa(page))
		query.Set("per", "1")
		parsed.RawQuery = query.Encode()
		code, document := railsTraceRequest(p.t, p.client, p.config.Endpoint, "GET", parsed.String(), token, nil)
		if code != 200 {
			p.t.Fatalf("Authenticated metric read failed (HTTP %d)", code)
		}
		values, ok := document["data"].([]any)
		if !ok {
			p.t.Fatal("Metric read did not return an array")
		}
		for _, value := range values {
			record, ok := value.(map[string]any)
			if !ok || record["api_schema_version"] != json.Number("1") {
				p.t.Fatal("Metric read did not match API schema version one")
			}
			records = append(records, record)
		}
		meta, _ := document["meta"].(map[string]any)
		pages, _ := strconv.Atoi(stringNumber(meta["total_pages"]))
		if page >= pages {
			return records
		}
	}
	p.t.Fatal("Metric pagination exceeded its budget")
	return nil
}

func stringNumber(value any) string {
	switch number := value.(type) {
	case string:
		return number
	case json.Number:
		return number.String()
	}
	return ""
}

func (p *metricPersistenceProof) series(name string) map[string]any {
	rows := p.list("/api/v1/measurement_series?name="+url.QueryEscape(name), p.config.ReadToken)
	if len(rows) != 1 || rows[0]["name"] != name {
		p.t.Fatal("Metric descriptor did not resolve exactly one series")
	}
	return rows[0]
}

func (p *metricPersistenceProof) points(series map[string]any, expected int) []map[string]any {
	id, ok := series["id"].(string)
	if !ok {
		p.t.Fatal("Metric series did not expose an identity")
	}
	rows := p.list("/api/v1/measurement_series/"+id+"/points", p.config.ReadToken)
	if len(rows) != expected {
		p.t.Fatalf("Persisted metric point count=%d expected=%d", len(rows), expected)
	}
	serialized, _ := json.Marshal(rows)
	if bytes.Contains(serialized, []byte(p.config.IngestToken)) {
		p.t.Fatal("Private metric readback contains the original credential")
	}
	return rows
}

func (p *metricPersistenceProof) aggregation(series map[string]any, from, to string) map[string]any {
	fromNano, errFrom := strconv.ParseInt(from, 10, 64)
	toNano, errTo := strconv.ParseInt(to, 10, 64)
	if errFrom != nil || errTo != nil {
		p.t.Fatal("Aggregation test requires observed integer nanoseconds")
	}
	query := url.Values{"from": {time.Unix(0, fromNano).UTC().Format(time.RFC3339Nano)}, "to": {time.Unix(0, toNano).UTC().Format(time.RFC3339Nano)}, "interval_seconds": {"60"}}
	status, document := railsTraceRequest(p.t, p.client, p.config.Endpoint, "GET", "/api/v1/measurement_series/"+series["id"].(string)+"/aggregation?"+query.Encode(), p.config.ReadToken, nil)
	if status != 200 {
		p.t.Fatalf("Metric aggregation failed (HTTP %d)", status)
	}
	data, _ := document["data"].(map[string]any)
	buckets, _ := data["buckets"].([]any)
	if data["api_schema_version"] != json.Number("1") || len(buckets) != 1 {
		p.t.Fatal("Metric aggregation did not return one versioned bucket")
	}
	return buckets[0].(map[string]any)
}

func (p *metricPersistenceProof) knownValue(bucket map[string]any) map[string]any {
	value, ok := bucket["value"].(map[string]any)
	if bucket["status"] != "known" || !ok {
		p.t.Fatal("Known metric measurements did not produce a known aggregation")
	}
	return value
}

func (p *metricPersistenceProof) verifyProtocol(protocol string) {
	prefix := "certification." + protocol
	client := p.officialClient(protocol, prefix, metricdata.CumulativeTemporality)
	meter := client.provider.Meter("certification-metrics", metricapi.WithInstrumentationVersion("1.2.3"), metricapi.WithSchemaURL("https://opentelemetry.io/schemas/1.40.0"))
	gauge, gaugeErr := meter.Int64Gauge(prefix+".gauge", metricapi.WithUnit("1"))
	counter, counterErr := meter.Int64Counter(prefix+".counter", metricapi.WithUnit("{request}"))
	histogram, histogramErr := meter.Float64Histogram(prefix+".explicit", metricapi.WithUnit("ms"))
	exponential, exponentialErr := meter.Float64Histogram(prefix+".exponential", metricapi.WithUnit("ms"))
	if gaugeErr != nil || counterErr != nil || histogramErr != nil || exponentialErr != nil {
		p.t.Fatal("Official SDK metric instruments could not be created")
	}
	ctx := context.Background()
	options := metricapi.WithAttributes(attribute.String("dimension", "known-values"))
	gauge.Record(ctx, 7, options)
	counter.Add(ctx, 10, options)
	histogram.Record(ctx, 2, options)
	histogram.Record(ctx, 8, options)
	exponential.Record(ctx, 1, options)
	exponential.Record(ctx, 4, options)
	first := p.collect(client)
	p.verifySnapshot(first.Body, 1)
	gauge.Record(ctx, 9, options)
	counter.Add(ctx, 5, options)
	histogram.Record(ctx, 2, options)
	exponential.Record(ctx, 1, options)
	second := p.collect(client)
	p.verifySnapshot(second.Body, 2)
	p.verifyKnownAggregations(prefix)
	p.closeClient(client)
	restarted := p.officialClient(protocol, prefix, metricdata.CumulativeTemporality)
	restartedMeter := restarted.provider.Meter("certification-metrics", metricapi.WithInstrumentationVersion("1.2.3"), metricapi.WithSchemaURL("https://opentelemetry.io/schemas/1.40.0"))
	restartedCounter, err := restartedMeter.Int64Counter(prefix+".counter", metricapi.WithUnit("{request}"))
	if err != nil {
		p.t.Fatal("Official SDK counter restart failed")
	}
	restartedCounter.Add(ctx, 3, options)
	p.collect(restarted)
	series := p.series(prefix + ".counter")
	points := p.points(series, 3)
	reset := p.aggregation(series, points[1]["time_unix_nano"].(string), points[2]["time_unix_nano"].(string))
	if reset["status"] != "unknown" || reset["value"] != nil {
		p.t.Fatal("Counter restart with an observation gap invented a known aggregate")
	}
	p.verifyDelta(protocol, prefix, options)
	p.verifyProtocolBoundaries(first.Body, second.Body, prefix)
	p.t.Logf("Metric assertions passed: protocol=%s gzip=true real_sdk_gauge_sum_delta_cumulative_explicit_exponential=true restart_conservative=true typed_private_readback=true", protocol)
}

func (p *metricPersistenceProof) verifyDelta(protocol, prefix string, options metricapi.MeasurementOption) {
	client := p.officialClient(protocol, prefix, metricdata.DeltaTemporality)
	meter := client.provider.Meter("certification-metrics", metricapi.WithInstrumentationVersion("1.2.3"), metricapi.WithSchemaURL("https://opentelemetry.io/schemas/1.40.0"))
	counter, err := meter.Int64Counter(prefix+".delta", metricapi.WithUnit("{request}"))
	if err != nil {
		p.t.Fatal("Official delta counter initialization failed")
	}
	counter.Add(context.Background(), 10, options)
	first := p.collect(client)
	counter.Add(context.Background(), 5, options)
	second := p.collect(client)
	series := p.series(prefix + ".delta")
	if series["temporality"] != json.Number("1") || series["monotonic"] != true {
		p.t.Fatal("Delta or monotonic counter semantics changed")
	}
	points := p.points(series, 2)
	value := p.knownValue(p.aggregation(series, points[0]["start_time_unix_nano"].(string), points[1]["time_unix_nano"].(string)))
	if stringNumber(value["sum"]) != "15" {
		p.t.Fatal("Contiguous delta measurements did not aggregate to fifteen")
	}
	p.verifyDeltaBoundaries(first.Body, second.Body, prefix)
}

func (p *metricPersistenceProof) verifyKnownAggregations(prefix string) {
	series := p.series(prefix + ".gauge")
	points := p.points(series, 2)
	start, _ := strconv.ParseInt(points[0]["time_unix_nano"].(string), 10, 64)
	value := p.knownValue(p.aggregation(series, strconv.FormatInt(start-1, 10), points[1]["time_unix_nano"].(string)))
	if stringNumber(value["last"]) != "9" || stringNumber(value["min"]) != "7" || stringNumber(value["max"]) != "9" {
		p.t.Fatal("Gauge aggregation did not preserve known last/min/max values")
	}
	series = p.series(prefix + ".counter")
	points = p.points(series, 2)
	value = p.knownValue(p.aggregation(series, points[0]["time_unix_nano"].(string), points[1]["time_unix_nano"].(string)))
	first, _ := strconv.ParseInt(points[0]["time_unix_nano"].(string), 10, 64)
	last, _ := strconv.ParseInt(points[1]["time_unix_nano"].(string), 10, 64)
	rate, rateErr := strconv.ParseFloat(stringNumber(value["rate"]), 64)
	expectedRate := 5e9 / float64(last-first)
	if stringNumber(value["sum"]) != "5" || rateErr != nil || math.IsNaN(rate) || math.IsInf(rate, 0) || last <= first || math.Abs(rate-expectedRate)/expectedRate > 1e-8 {
		p.t.Fatal("Cumulative counter delta or rate did not match observed values and time")
	}
	for _, name := range []string{"explicit", "exponential"} {
		series = p.series(prefix + "." + name)
		points = p.points(series, 2)
		value = p.knownValue(p.aggregation(series, points[0]["start_time_unix_nano"].(string), points[0]["time_unix_nano"].(string)))
		expectedSum := "10"
		if name == "exponential" {
			expectedSum = "5"
		}
		if stringNumber(value["count"]) != "2" || stringNumber(value["sum"]) != expectedSum {
			p.t.Fatal("SDK histogram aggregate lost its known count or sum")
		}
		if name == "explicit" {
			counts, _ := value["bucketCounts"].([]any)
			if len(counts) != 3 || stringNumber(counts[0]) != "1" || stringNumber(counts[1]) != "1" || stringNumber(counts[2]) != "0" {
				p.t.Fatal("Explicit histogram aggregation changed the original buckets")
			}
		}
	}
}

func (p *metricPersistenceProof) verifySnapshot(body []byte, count int) {
	var document map[string]any
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	if decoder.Decode(&document) != nil {
		p.t.Fatal("Cannot inspect original SDK metric JSON")
	}
	resourceMetrics := document["resourceMetrics"].([]any)[0].(map[string]any)
	scopeMetrics := resourceMetrics["scopeMetrics"].([]any)[0].(map[string]any)
	for _, item := range scopeMetrics["metrics"].([]any) {
		metric := item.(map[string]any)
		series := p.series(metric["name"].(string))
		points := p.points(series, count)
		kind := metricKind(metric)
		if series["metric_type"] != kind || series["unit"] != metric["unit"] {
			p.t.Fatal("Metric descriptor type or unit changed")
		}
		descriptor := metric[kind].(map[string]any)
		if kind != "gauge" && stringNumber(series["temporality"]) != stringNumber(descriptor["aggregationTemporality"]) {
			p.t.Fatal("Metric aggregation temporality changed")
		}
		if kind == "sum" && series["monotonic"] != descriptor["isMonotonic"] {
			p.t.Fatal("Metric sum monotonicity changed")
		}
		original := metric[kind].(map[string]any)["dataPoints"].([]any)[0].(map[string]any)
		var found map[string]any
		for _, point := range points {
			if point["time_unix_nano"] == original["timeUnixNano"] {
				found = point
			}
		}
		if found == nil || found["start_time_unix_nano"] != defaultNano(original["startTimeUnixNano"]) {
			p.t.Fatal("Nanosecond metric point identity changed")
		}
		observedResource := deepMetricCopy(resourceMetrics)
		observedScope := observedResource["scopeMetrics"].([]any)[0].(map[string]any)
		observedMetric := deepMetricCopy(metric)
		observedResource["resource"] = series["resource"]
		observedResource["schemaUrl"] = series["resource_schema_url"]
		observedScope["schemaUrl"] = series["scope_schema_url"]
		observedScope["scope"] = series["instrumentation_scope"]
		observedScope["metrics"] = []any{observedMetric}
		observedMetric[kind].(map[string]any)["dataPoints"] = []any{found["payload"]}
		originalResource := deepMetricCopy(resourceMetrics)
		originalResource["scopeMetrics"].([]any)[0].(map[string]any)["metrics"] = []any{metric}
		if !reflect.DeepEqual(canonicalMetricJSON(p.t, originalResource), canonicalMetricJSON(p.t, observedResource)) {
			p.t.Fatal("Resource, scope or typed metric payload changed during persistence")
		}
	}
}

func defaultNano(value any) string {
	if value == nil {
		return "0"
	}
	return stringNumber(value)
}

func metricKind(metric map[string]any) string {
	for _, kind := range []string{"gauge", "sum", "histogram", "exponentialHistogram", "summary"} {
		if _, exists := metric[kind]; exists {
			return kind
		}
	}
	return ""
}

func deepMetricCopy(value map[string]any) map[string]any {
	encoded, _ := json.Marshal(value)
	var result map[string]any
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	_ = decoder.Decode(&result)
	return result
}

func canonicalMetricJSON(t *testing.T, resourceMetrics map[string]any) any {
	encoded, _ := json.Marshal(map[string]any{"resourceMetrics": []any{resourceMetrics}})
	request := pmetricotlp.NewExportRequest()
	if request.UnmarshalJSON(encoded) != nil {
		t.Fatal("Private metric projection is not valid OTLP")
	}
	canonical, err := request.MarshalJSON()
	if err != nil {
		t.Fatal("Cannot canonicalize metric projection")
	}
	var result any
	decoder := json.NewDecoder(bytes.NewReader(canonical))
	decoder.UseNumber()
	if decoder.Decode(&result) != nil {
		t.Fatal("Cannot inspect canonical metric projection")
	}
	sortTraceAttributes(result)
	return result
}

// These cases derive protocol fixtures from observed official SDK exports. They
// exercise receiver and Rails boundaries that normal SDK instruments cannot emit.
func (p *metricPersistenceProof) metricFixture(body []byte, name string) (pmetricotlp.ExportRequest, pmetric.Metric) {
	request := pmetricotlp.NewExportRequest()
	if request.UnmarshalJSON(body) != nil {
		p.t.Fatal("Cannot decode an observed SDK metric export")
	}
	metrics := request.Metrics().ResourceMetrics().At(0).ScopeMetrics().At(0).Metrics()
	metrics.RemoveIf(func(metric pmetric.Metric) bool { return metric.Name() != name })
	if metrics.Len() != 1 {
		p.t.Fatal("Protocol fixture did not select exactly one observed metric")
	}
	return request, metrics.At(0)
}

func (p *metricPersistenceProof) postFixture(request pmetricotlp.ExportRequest, token string, rejected int64, queued bool) {
	body, err := request.MarshalJSON()
	if err != nil {
		p.t.Fatal("Cannot encode the derived metric protocol case")
	}
	code, response := p.h.post(p.t, "metrics", body, "application/json", "", "Bearer "+token)
	result := pmetricotlp.NewExportResponse()
	if code != 200 || result.UnmarshalJSON(response) != nil || result.PartialSuccess().RejectedDataPoints() != rejected {
		p.t.Fatalf("Metric protocol admission failed (HTTP %d)", code)
	}
	if queued {
		nextObservedTrace(p.t, p.observed)
	}
	assertTraceQueueEmpty(p.t, p.h)
}

func (p *metricPersistenceProof) unknown(series map[string]any, from, to, diagnostic string) {
	bucket := p.aggregation(series, from, to)
	found := false
	for _, value := range bucket["diagnostics"].([]any) {
		found = found || value == diagnostic
	}
	if bucket["status"] != "unknown" || bucket["value"] != nil || !found {
		p.t.Fatalf("Metric boundary did not remain unknown with diagnostic %s", diagnostic)
	}
}

func (p *metricPersistenceProof) verifyProtocolBoundaries(first, second []byte, prefix string) {
	request, metric := p.metricFixture(first, prefix+".gauge")
	series := p.series(prefix + ".gauge")
	before := p.points(series, 2)
	lastTime, _ := strconv.ParseInt(before[1]["time_unix_nano"].(string), 10, 64)
	p.unknown(series, strconv.FormatInt(lastTime, 10), strconv.FormatInt(lastTime+10, 10), "no_data")
	p.postFixture(request, p.config.IngestToken, 0, true)
	metric.SetDescription("Protocol-only description change")
	p.postFixture(request, p.config.IngestToken, 0, true)
	after := p.points(p.series(prefix+".gauge"), 2)
	if !reflect.DeepEqual(before, after) {
		p.t.Fatal("Duplicate metric replay changed stored points or their receipt time")
	}

	_, secondMetric := p.metricFixture(second, prefix+".gauge")
	original := metric.Gauge().DataPoints().At(0)
	accepted := metric.Gauge().DataPoints().AppendEmpty()
	original.CopyTo(accepted)
	accepted.SetTimestamp(secondMetric.Gauge().DataPoints().At(0).Timestamp() + 1)
	accepted.SetIntValue(12)
	original.SetIntValue(99)
	_, _, rejectedBefore, _ := p.recorder.counts()
	p.postFixture(request, p.config.IngestToken, 0, true)
	_, _, rejectedAfter, _ := p.recorder.counts()
	if rejectedAfter != rejectedBefore+1 {
		p.t.Fatal("Real metric delivery did not diagnose the conflicting point")
	}
	rows := p.points(series, 3)
	foundOriginal, foundAccepted := false, false
	for _, row := range rows {
		payload := row["payload"].(map[string]any)
		foundOriginal = foundOriginal || (row["time_unix_nano"] == strconv.FormatUint(uint64(original.Timestamp()), 10) && stringNumber(payload["asInt"]) == "7")
		foundAccepted = foundAccepted || (row["time_unix_nano"] == strconv.FormatUint(uint64(accepted.Timestamp()), 10) && stringNumber(payload["asInt"]) == "12")
	}
	if !foundOriginal || !foundAccepted {
		p.t.Fatal("Partial metric rejection overwrote or lost an independently valid point")
	}

	originalRequest, _ := p.metricFixture(first, prefix+".gauge")
	if len(p.list("/api/v1/measurement_series?name="+url.QueryEscape(prefix+".gauge"), p.config.OtherReadToken)) != 0 {
		p.t.Fatal("Metric series leaked across projects")
	}
	path := "/api/v1/measurement_series/" + series["id"].(string)
	for _, suffix := range []string{"", "/points", "/aggregation?from=2026-01-01T00:00:00Z&to=2026-01-01T00:01:00Z&interval_seconds=60"} {
		status, _ := railsTraceRequest(p.t, p.client, p.config.Endpoint, "GET", path+suffix, p.config.OtherReadToken, nil)
		if status != 404 {
			p.t.Fatal("Another project could address the private metric series")
		}
	}
	for _, token := range []string{"", p.config.PublicKey, p.config.IngestToken} {
		status, _ := railsTraceRequest(p.t, p.client, p.config.Endpoint, "GET", path, token, nil)
		if status != 401 && status != 403 {
			p.t.Fatal("Private metrics were accessible without read scope")
		}
	}
	body, _ := originalRequest.MarshalJSON()
	status, _ := railsTraceRequest(p.t, p.client, p.config.Endpoint, "POST", "/api/v1/projects/"+p.config.OtherProjectID+"/otlp/metrics", p.config.IngestToken, body)
	if status != 404 {
		p.t.Fatal("Metric ingestion accepted a credential belonging to another project")
	}
	p.postFixture(originalRequest, p.config.OtherIngestToken, 0, true)
	other := p.list("/api/v1/measurement_series?name="+url.QueryEscape(prefix+".gauge"), p.config.OtherReadToken)
	if len(other) != 1 || other[0]["id"] == series["id"] {
		p.t.Fatal("Identical metric descriptors were not isolated by project")
	}
	otherPoints := p.list("/api/v1/measurement_series/"+other[0]["id"].(string)+"/points", p.config.OtherReadToken)
	if len(otherPoints) != 1 || otherPoints[0]["time_unix_nano"] != before[0]["time_unix_nano"] {
		p.t.Fatal("Isolated metric point was not persisted independently")
	}
	p.points(series, 3)

	unrecorded, unrecordedMetric := p.metricFixture(first, prefix+".gauge")
	unrecordedMetric.SetName(prefix + ".unrecorded")
	point := unrecordedMetric.Gauge().DataPoints().At(0)
	point.SetFlags(pmetric.DataPointFlags(1))
	p.postFixture(unrecorded, p.config.IngestToken, 0, true)
	p.unknown(p.series(prefix+".unrecorded"), strconv.FormatUint(uint64(point.Timestamp())-1, 10), strconv.FormatUint(uint64(point.Timestamp()), 10), "no_recorded_value")

	summary, summaryMetric := p.metricFixture(first, prefix+".gauge")
	summaryMetric.SetName(prefix + ".summary")
	summaryPoint := summaryMetric.SetEmptySummary().DataPoints().AppendEmpty()
	summaryPoint.SetTimestamp(point.Timestamp())
	summaryPoint.SetCount(1)
	summaryPoint.SetSum(7)
	p.postFixture(summary, p.config.IngestToken, 1, false)
	if len(p.list("/api/v1/measurement_series?name="+url.QueryEscape(prefix+".summary"), p.config.ReadToken)) != 0 {
		p.t.Fatal("Unsupported summary metric was persisted")
	}

	p.verifyExponentialRebin(first, second, prefix)
	for _, kind := range []string{"explicit", "exponential"} {
		layout, layoutMetric := p.metricFixture(first, prefix+"."+kind)
		_, next := p.metricFixture(second, prefix+"."+kind)
		layoutMetric.SetName(prefix + "." + kind + ".layout")
		var from, to string
		if kind == "explicit" {
			points := layoutMetric.Histogram().DataPoints()
			changed := points.AppendEmpty()
			next.Histogram().DataPoints().At(0).CopyTo(changed)
			changed.ExplicitBounds().SetAt(0, 4)
			from, to = strconv.FormatUint(uint64(points.At(0).Timestamp()), 10), strconv.FormatUint(uint64(changed.Timestamp()), 10)
		} else {
			points := layoutMetric.ExponentialHistogram().DataPoints()
			changed := points.AppendEmpty()
			next.ExponentialHistogram().DataPoints().At(0).CopyTo(changed)
			changed.SetZeroThreshold(changed.ZeroThreshold() + 0.001)
			from, to = strconv.FormatUint(uint64(points.At(0).Timestamp()), 10), strconv.FormatUint(uint64(changed.Timestamp()), 10)
		}
		p.postFixture(layout, p.config.IngestToken, 0, true)
		layoutSeries := p.series(prefix + "." + kind + ".layout")
		p.points(layoutSeries, 2)
		p.unknown(layoutSeries, from, to, "incompatible_layout")
	}
}

func (p *metricPersistenceProof) verifyDeltaBoundaries(first, second []byte, prefix string) {
	for _, boundary := range []string{"gap", "overlap"} {
		fixture, metric := p.metricFixture(first, prefix+".delta")
		_, next := p.metricFixture(second, prefix+".delta")
		metric.SetName(prefix + ".delta." + boundary)
		points := metric.Sum().DataPoints()
		changed := points.AppendEmpty()
		next.Sum().DataPoints().At(0).CopyTo(changed)
		if boundary == "gap" {
			changed.SetStartTimestamp(points.At(0).Timestamp() + 1)
		} else {
			changed.SetStartTimestamp(points.At(0).Timestamp() - 1)
		}
		p.postFixture(fixture, p.config.IngestToken, 0, true)
		series := p.series(prefix + ".delta." + boundary)
		p.points(series, 2)
		p.unknown(series, strconv.FormatUint(uint64(points.At(0).StartTimestamp()), 10), strconv.FormatUint(uint64(changed.Timestamp()), 10), boundary)
	}
}

func (p *metricPersistenceProof) verifyExponentialRebin(first, second []byte, prefix string) {
	fixture, metric := p.metricFixture(first, prefix+".exponential")
	_, next := p.metricFixture(second, prefix+".exponential")
	metric.SetName(prefix + ".exponential.rebin")
	points := metric.ExponentialHistogram().DataPoints()
	changed := points.AppendEmpty()
	next.ExponentialHistogram().DataPoints().At(0).CopyTo(changed)
	// Adjacent buckets merge without inventing observations. The resulting layout
	// describes the same SDK observations at one coarser exponential scale.
	for _, buckets := range []pmetric.ExponentialHistogramDataPointBuckets{changed.Positive(), changed.Negative()} {
		if buckets.BucketCounts().Len() == 0 {
			continue
		}
		merged := make(map[int32]uint64)
		firstIndex := buckets.Offset() >> 1
		lastIndex := (buckets.Offset() + int32(buckets.BucketCounts().Len()) - 1) >> 1
		for index := 0; index < buckets.BucketCounts().Len(); index++ {
			merged[(buckets.Offset()+int32(index))>>1] += buckets.BucketCounts().At(index)
		}
		values := make([]uint64, lastIndex-firstIndex+1)
		for index := range values {
			values[index] = merged[firstIndex+int32(index)]
		}
		buckets.SetOffset(firstIndex)
		buckets.BucketCounts().FromRaw(values)
	}
	changed.SetScale(changed.Scale() - 1)
	p.postFixture(fixture, p.config.IngestToken, 0, true)
	series := p.series(prefix + ".exponential.rebin")
	p.points(series, 2)
	value := p.knownValue(p.aggregation(series, strconv.FormatUint(uint64(points.At(0).Timestamp()), 10), strconv.FormatUint(uint64(changed.Timestamp()), 10)))
	if stringNumber(value["count"]) != "1" || stringNumber(value["sum"]) != "1" || stringNumber(value["scale"]) != strconv.Itoa(int(changed.Scale())) {
		p.t.Fatal("Exponential scale reconciliation lost the observed count, sum or coarser scale")
	}
	bucketCount := uint64(0)
	for _, key := range []string{"positive", "negative"} {
		buckets := value[key].(map[string]any)
		offset, err := strconv.ParseInt(stringNumber(buckets["offset"]), 10, 32)
		if err != nil {
			p.t.Fatal("Reconciled exponential offset is not an integer")
		}
		for index, count := range buckets["bucketCounts"].([]any) {
			parsed, err := strconv.ParseUint(stringNumber(count), 10, 64)
			if err != nil {
				p.t.Fatal("Reconciled exponential bucket is not an unsigned count")
			}
			// The only new observation is exactly +1, whose upper-inclusive
			// exponential bucket is index -1 at every supported scale.
			if parsed > 0 && (key != "positive" || offset+int64(index) != -1 || parsed != 1) {
				p.t.Fatal("Reconciled exponential distribution moved the known observation")
			}
			bucketCount += parsed
		}
	}
	zero, _ := strconv.ParseUint(stringNumber(value["zeroCount"]), 10, 64)
	threshold, thresholdErr := strconv.ParseFloat(stringNumber(value["zeroThreshold"]), 64)
	if bucketCount != 1 || zero != 0 || thresholdErr != nil || threshold != 0 {
		p.t.Fatal("Reconciled exponential distribution lost its single new observation")
	}
}

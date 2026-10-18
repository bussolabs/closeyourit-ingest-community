// Package metrics publishes the operational health of the gateway in Prometheus
// format.
//
// Exposure is pull on a separate listener, never push towards CloseYourIt:
// the telemetry that describes the ingest cannot go through the ingest, otherwise
// the failure to report is also the one that wipes out the report. For the
// same reason the metrics listener does not go through Caddy and is not
// reachable from the Internet.
package metrics

import (
	"net/http"
	"time"

	"github.com/bussolabs/closeyourit-ingest-community/gateway/internal/version"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// The buckets cover the configured timeouts: 3s for direct forwarding, 15s for
// delivery. Beyond the cap the count in +Inf remains anyway.
var (
	httpBuckets    = []float64{0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2, 3, 5, 10, 15}
	publishBuckets = []float64{0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5}
	// The upstream's Retry-After is minutes, not milliseconds: it is a declared
	// wait, not a measured latency.
	retryAfterBuckets = []float64{1, 5, 15, 30, 60, 120, 300, 600, 1800, 3600}
)

type Recorder struct {
	registry             *prometheus.Registry
	otlpItems            *prometheus.CounterVec
	otlpRequests         *prometheus.CounterVec
	otlpDeliveryRejected *prometheus.CounterVec

	requests        *prometheus.CounterVec
	rejected        *prometheus.CounterVec
	upstreamStatus  *prometheus.CounterVec
	upstreamLatency *prometheus.HistogramVec
	publishLatency  *prometheus.HistogramVec
	publishFailures *prometheus.CounterVec
	retryAfter      *prometheus.HistogramVec

	directProxyHealthy prometheus.Gauge
	queueConnected     prometheus.Gauge
	draining           prometheus.Gauge

	deliveries       *prometheus.CounterVec
	deliveryFailures *prometheus.CounterVec
	workers          prometheus.Gauge
	workersBusy      prometheus.Gauge

	natsDisconnects prometheus.Counter
	natsReconnects  prometheus.Counter

	streamMessages   *prometheus.GaugeVec
	streamBytes      *prometheus.GaugeVec
	streamLimitBytes *prometheus.GaugeVec
	streamOldestAge  *prometheus.GaugeVec
	consumerPending  *prometheus.GaugeVec
	consumerAck      *prometheus.GaugeVec
	consumerRedeliv  *prometheus.GaugeVec
	statsFailures    prometheus.Counter
}

func New() *Recorder {
	r := &Recorder{registry: prometheus.NewRegistry()}
	r.otlpDeliveryRejected = counterVec("ingest_otlp_delivery_rejected_items_total", "OTLP items rejected after durable admission.", "kind")
	r.otlpRequests = counterVec("ingest_otlp_requests_total", "OTLP exports by signal and protocol status.", "signal", "status")
	r.otlpItems = counterVec("ingest_otlp_items_total", "OTLP items by signal and admission outcome.", "signal", "outcome")

	r.requests = counterVec("ingest_requests_total",
		"Requests accepted by the gateway by telemetry kind and outcome: direct, queued or dropped.",
		"kind", "outcome")
	r.rejected = counterVec("ingest_rejected_requests_total",
		"Requests refused before reaching the upstream or the queue, by reason.", "reason")
	r.upstreamStatus = counterVec("ingest_upstream_responses_total",
		"CloseYourIt upstream answers by source (direct or delivery), kind and HTTP code; status=error means a network failure.",
		"source", "kind", "status")
	r.upstreamLatency = histogramVec("ingest_upstream_duration_seconds",
		"Duration of the HTTP call to the upstream, by source and kind.", httpBuckets, "source", "kind")
	r.publishLatency = histogramVec("ingest_publish_duration_seconds",
		"Duration of the JetStream publish, successful or failed.", publishBuckets, "kind")
	r.publishFailures = counterVec("ingest_publish_failures_total",
		"Failed JetStream publishes: with DiscardNew a full stream refuses new messages.", "kind")
	r.retryAfter = histogramVec("ingest_retry_after_seconds",
		"Wait asked by the upstream with the Retry-After header, by source.", retryAfterBuckets, "source")

	r.directProxyHealthy = gauge("ingest_direct_proxy_healthy",
		"1 when the last direct forward to the upstream succeeded or the failure observation expired.")
	r.queueConnected = gauge("ingest_queue_connected",
		"1 while the NATS connection is up: it is also the queue state reported by /ready.")
	r.draining = gauge("ingest_draining", "1 while the gateway drains in-flight requests before stopping.")

	r.deliveries = counterVec("ingest_deliveries_total",
		"Deferred delivery outcomes by kind: delivered, retried or dead_lettered.", "kind", "outcome")
	r.deliveryFailures = counterVec("ingest_delivery_failure_reasons_total",
		"Reason of failed delivery attempts: HTTP code, network error or unreadable message.", "reason")
	r.workers = gauge("ingest_delivery_workers", "Configured delivery workers.")
	r.workersBusy = gauge("ingest_delivery_workers_busy",
		"Delivery workers busy with a message: against the total it measures saturation.")

	r.natsDisconnects = counter("ingest_nats_disconnects_total", "NATS disconnections seen by the client.")
	r.natsReconnects = counter("ingest_nats_reconnects_total", "Successful NATS reconnections.")

	r.streamMessages = gaugeVec("ingest_stream_messages", "Messages in the stream.", "stream")
	r.streamBytes = gaugeVec("ingest_stream_bytes", "Bytes used by the stream.", "stream")
	r.streamLimitBytes = gaugeVec("ingest_stream_limit_bytes",
		"Byte cap of the stream: once reached, DiscardNew refuses new messages.", "stream")
	r.streamOldestAge = gaugeVec("ingest_stream_oldest_message_age_seconds",
		"Age of the oldest message still queued, 0 when the stream is empty.", "stream")
	r.consumerPending = gaugeVec("ingest_consumer_pending_messages", "Messages still to deliver to the consumer.", "stream", "consumer")
	r.consumerAck = gaugeVec("ingest_consumer_ack_pending_messages", "Messages delivered and waiting for ACK.", "stream", "consumer")
	r.consumerRedeliv = gaugeVec("ingest_consumer_redelivered_messages", "Messages redelivered at least once.", "stream", "consumer")
	r.statsFailures = counter("ingest_stream_stats_failures_total",
		"Failed JetStream state reads: the stream values stay those of the last successful read.")

	buildInfo := gaugeVec("ingest_build_info", "Identity of the running build, always 1.",
		"app", "tag", "sha", "build_time", "environment", "go_version")
	build := version.Info()
	buildInfo.WithLabelValues(build.App, build.Tag, build.SHA, build.BuildTime, build.Environment, build.GoVersion).Set(1)

	r.registry.MustRegister(r.otlpItems, r.otlpRequests, r.otlpDeliveryRejected,
		r.requests, r.rejected, r.upstreamStatus, r.upstreamLatency,
		r.publishLatency, r.publishFailures, r.retryAfter,
		r.directProxyHealthy, r.queueConnected, r.draining,
		r.deliveries, r.deliveryFailures, r.workers, r.workersBusy,
		r.natsDisconnects, r.natsReconnects,
		r.streamMessages, r.streamBytes, r.streamLimitBytes, r.streamOldestAge,
		r.consumerPending, r.consumerAck, r.consumerRedeliv, r.statsFailures,
		buildInfo,
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)
	return r
}

func (r *Recorder) Handler() http.Handler {
	return promhttp.HandlerFor(r.registry, promhttp.HandlerOpts{ErrorHandling: promhttp.HTTPErrorOnError})
}

func (r *Recorder) RecordRequest(kind, outcome string) {
	r.requests.WithLabelValues(kind, outcome).Inc()
}

func (r *Recorder) RecordRejected(reason string) {
	r.rejected.WithLabelValues(reason).Inc()
}

func (r *Recorder) RecordUpstream(source, kind, status string, duration time.Duration) {
	r.upstreamStatus.WithLabelValues(source, kind, status).Inc()
	r.upstreamLatency.WithLabelValues(source, kind).Observe(duration.Seconds())
}

func (r *Recorder) RecordPublish(kind string, duration time.Duration, err error) {
	r.publishLatency.WithLabelValues(kind).Observe(duration.Seconds())
	if err != nil {
		r.publishFailures.WithLabelValues(kind).Inc()
	}
}

func (r *Recorder) RecordRetryAfter(source string, delay time.Duration) {
	r.retryAfter.WithLabelValues(source).Observe(delay.Seconds())
}

func (r *Recorder) SetReadiness(directProxyHealthy, queueConnected, draining bool) {
	r.directProxyHealthy.Set(boolValue(directProxyHealthy))
	r.queueConnected.Set(boolValue(queueConnected))
	r.draining.Set(boolValue(draining))
}

// The attempt duration is already in ingest_upstream_duration_seconds with
// source="delivery": measuring it twice would create two truths about the same
// fact, and sooner or later they would diverge.
func (r *Recorder) RecordDelivery(kind, outcome string) {
	r.deliveries.WithLabelValues(kind, outcome).Inc()
}

func (r *Recorder) RecordDeliveryFailure(reason string) {
	r.deliveryFailures.WithLabelValues(reason).Inc()
}

func (r *Recorder) SetDeliveryWorkers(total int) {
	r.workers.Set(float64(total))
}

func (r *Recorder) AddBusyDeliveryWorkers(delta int) {
	r.workersBusy.Add(float64(delta))
}

func (r *Recorder) RecordNATSDisconnect() { r.natsDisconnects.Inc() }

func (r *Recorder) RecordNATSReconnect() { r.natsReconnects.Inc() }

func boolValue(value bool) float64 {
	if value {
		return 1
	}
	return 0
}

func counter(name, help string) prometheus.Counter {
	return prometheus.NewCounter(prometheus.CounterOpts{Name: name, Help: help})
}

func counterVec(name, help string, labels ...string) *prometheus.CounterVec {
	return prometheus.NewCounterVec(prometheus.CounterOpts{Name: name, Help: help}, labels)
}

func gauge(name, help string) prometheus.Gauge {
	return prometheus.NewGauge(prometheus.GaugeOpts{Name: name, Help: help})
}

func gaugeVec(name, help string, labels ...string) *prometheus.GaugeVec {
	return prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: name, Help: help}, labels)
}

func histogramVec(name, help string, buckets []float64, labels ...string) *prometheus.HistogramVec {
	return prometheus.NewHistogramVec(prometheus.HistogramOpts{Name: name, Help: help, Buckets: buckets}, labels)
}

func (r *Recorder) RecordOTLP(signal, outcome string, count int) {
	r.otlpItems.WithLabelValues(signal, outcome).Add(float64(count))
}

func (r *Recorder) RecordOTLPRequest(signal, outcome string) {
	r.otlpRequests.WithLabelValues(signal, outcome).Inc()
}

func (r *Recorder) RecordOTLPDeliveryRejected(kind string, count int64) {
	r.otlpDeliveryRejected.WithLabelValues(kind).Add(float64(count))
}

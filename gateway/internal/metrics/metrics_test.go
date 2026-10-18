package metrics

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bussolabs/closeyourit-ingest-community/gateway/internal/queue"
)

func scrape(t *testing.T, recorder *Recorder) string {
	t.Helper()
	response := httptest.NewRecorder()
	recorder.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("scrape status=%d", response.Code)
	}
	return response.Body.String()
}

func requireSample(t *testing.T, body, sample string) {
	t.Helper()
	for line := range strings.SplitSeq(body, "\n") {
		if line == sample {
			return
		}
	}
	t.Fatalf("sample missing from the scrape: %q", sample)
}

func TestRecorderTellsDirectForwardingFromQueueingAndDrop(t *testing.T) {
	recorder := New()

	recorder.RecordRequest("logs", "direct")
	recorder.RecordRequest("logs", "queued")
	recorder.RecordRequest("logs", "queued")
	recorder.RecordRequest("sentry", "dropped")

	body := scrape(t, recorder)
	requireSample(t, body, `ingest_requests_total{kind="logs",outcome="direct"} 1`)
	requireSample(t, body, `ingest_requests_total{kind="logs",outcome="queued"} 2`)
	requireSample(t, body, `ingest_requests_total{kind="sentry",outcome="dropped"} 1`)
}

func TestRecorderRecordsUpstreamStatusAndLatencyBySource(t *testing.T) {
	recorder := New()

	recorder.RecordUpstream("direct", "logs", "502", 900*time.Millisecond)
	recorder.RecordUpstream("delivery", "logs", "200", 2*time.Second)

	body := scrape(t, recorder)
	requireSample(t, body, `ingest_upstream_responses_total{kind="logs",source="direct",status="502"} 1`)
	requireSample(t, body, `ingest_upstream_responses_total{kind="logs",source="delivery",status="200"} 1`)
	requireSample(t, body, `ingest_upstream_duration_seconds_count{kind="logs",source="direct"} 1`)
	requireSample(t, body, `ingest_upstream_duration_seconds_sum{kind="logs",source="delivery"} 2`)
}

func TestRecorderSeparatesPublishLatencyFromFailures(t *testing.T) {
	recorder := New()

	recorder.RecordPublish("metrics", 30*time.Millisecond, nil)
	recorder.RecordPublish("metrics", 40*time.Millisecond, errors.New("stream pieno"))

	body := scrape(t, recorder)
	requireSample(t, body, `ingest_publish_duration_seconds_count{kind="metrics"} 2`)
	requireSample(t, body, `ingest_publish_failures_total{kind="metrics"} 1`)
}

func TestRecorderObservesTheRetryAfterRequestedByTheUpstream(t *testing.T) {
	recorder := New()

	recorder.RecordRetryAfter("delivery", 120*time.Second)

	body := scrape(t, recorder)
	requireSample(t, body, `ingest_retry_after_seconds_count{source="delivery"} 1`)
	requireSample(t, body, `ingest_retry_after_seconds_sum{source="delivery"} 120`)
}

func TestRecorderCountsRequestsRejectedAtIngress(t *testing.T) {
	recorder := New()

	recorder.RecordRejected("rate_limited")
	recorder.RecordRejected("rate_limited")
	recorder.RecordRejected("body_too_large")

	body := scrape(t, recorder)
	requireSample(t, body, `ingest_rejected_requests_total{reason="rate_limited"} 2`)
	requireSample(t, body, `ingest_rejected_requests_total{reason="body_too_large"} 1`)
}

func TestRecorderPublishesTheStateOfBothPaths(t *testing.T) {
	recorder := New()

	recorder.SetReadiness(false, true, true)

	body := scrape(t, recorder)
	requireSample(t, body, `ingest_direct_proxy_healthy 0`)
	requireSample(t, body, `ingest_queue_connected 1`)
	requireSample(t, body, `ingest_draining 1`)
}

func TestRecorderRecordsDeliveryOutcomesAndReasons(t *testing.T) {
	recorder := New()

	recorder.RecordDelivery("events", "delivered")
	recorder.RecordDelivery("events", "retried")
	recorder.RecordDelivery("events", "dead_lettered")
	recorder.RecordDeliveryFailure("http_503")
	recorder.RecordDeliveryFailure("decrypt_failed")

	body := scrape(t, recorder)
	requireSample(t, body, `ingest_deliveries_total{kind="events",outcome="delivered"} 1`)
	requireSample(t, body, `ingest_deliveries_total{kind="events",outcome="retried"} 1`)
	requireSample(t, body, `ingest_deliveries_total{kind="events",outcome="dead_lettered"} 1`)
	requireSample(t, body, `ingest_delivery_failure_reasons_total{reason="http_503"} 1`)
	requireSample(t, body, `ingest_delivery_failure_reasons_total{reason="decrypt_failed"} 1`)
}

func TestRecorderExposesWorkerSaturation(t *testing.T) {
	recorder := New()

	recorder.SetDeliveryWorkers(4)
	recorder.AddBusyDeliveryWorkers(1)
	recorder.AddBusyDeliveryWorkers(1)
	recorder.AddBusyDeliveryWorkers(-1)

	body := scrape(t, recorder)
	requireSample(t, body, `ingest_delivery_workers 4`)
	requireSample(t, body, `ingest_delivery_workers_busy 1`)
}

func TestRecorderCountsNATSDisconnectionsAndReconnections(t *testing.T) {
	recorder := New()

	recorder.RecordNATSDisconnect()
	recorder.RecordNATSReconnect()

	body := scrape(t, recorder)
	requireSample(t, body, `ingest_nats_disconnects_total 1`)
	requireSample(t, body, `ingest_nats_reconnects_total 1`)
}

func TestRecorderExposesTheBuildIdentity(t *testing.T) {
	body := scrape(t, New())

	if !strings.Contains(body, "ingest_build_info{") {
		t.Fatal("ingest_build_info missing from the scrape")
	}
}

type fakeStats struct {
	stats queue.StoreStats
	err   error
	calls int
}

func (f *fakeStats) Stats(context.Context) (queue.StoreStats, error) {
	f.calls++
	return f.stats, f.err
}

func TestRefreshStatsPublishesStreamDepthAgeAndLimit(t *testing.T) {
	recorder := New()
	reader := &fakeStats{stats: queue.StoreStats{
		Streams: []queue.StreamStats{{
			Name: "CYI_INGEST", Messages: 128, Bytes: 4096,
			LimitBytes: 25 * 1024 * 1024 * 1024, OldestAge: 90 * time.Second,
		}},
		Consumers: []queue.ConsumerStats{{
			Stream: "CYI_INGEST", Name: "delivery-v1", Pending: 12, AckPending: 3, Redelivered: 5,
		}},
	}}

	recorder.RefreshStats(context.Background(), reader)

	body := scrape(t, recorder)
	requireSample(t, body, `ingest_stream_messages{stream="CYI_INGEST"} 128`)
	requireSample(t, body, `ingest_stream_bytes{stream="CYI_INGEST"} 4096`)
	requireSample(t, body, `ingest_stream_limit_bytes{stream="CYI_INGEST"} 2.68435456e+10`)
	requireSample(t, body, `ingest_stream_oldest_message_age_seconds{stream="CYI_INGEST"} 90`)
	requireSample(t, body, `ingest_consumer_pending_messages{consumer="delivery-v1",stream="CYI_INGEST"} 12`)
	requireSample(t, body, `ingest_consumer_ack_pending_messages{consumer="delivery-v1",stream="CYI_INGEST"} 3`)
	requireSample(t, body, `ingest_consumer_redelivered_messages{consumer="delivery-v1",stream="CYI_INGEST"} 5`)
	requireSample(t, body, `ingest_stream_stats_failures_total 0`)
}

func TestRefreshStatsCountsFailuresWithoutResettingTheLastState(t *testing.T) {
	recorder := New()
	reader := &fakeStats{stats: queue.StoreStats{
		Streams: []queue.StreamStats{{Name: "CYI_INGEST", Messages: 7}},
	}}
	recorder.RefreshStats(context.Background(), reader)

	reader.err = errors.New("JetStream irraggiungibile")
	recorder.RefreshStats(context.Background(), reader)

	body := scrape(t, recorder)
	requireSample(t, body, `ingest_stream_messages{stream="CYI_INGEST"} 7`)
	requireSample(t, body, `ingest_stream_stats_failures_total 1`)
}

func TestRefreshStatsDoesNotReportAFailureDuringShutdown(t *testing.T) {
	recorder := New()
	reader := &fakeStats{err: errors.New("contesto chiuso")}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	recorder.RefreshStats(ctx, reader)

	if reader.calls != 1 {
		t.Fatalf("reads=%d", reader.calls)
	}
	requireSample(t, scrape(t, recorder), `ingest_stream_stats_failures_total 0`)
}

package natsstore

import (
	"testing"
	"time"

	"github.com/nats-io/nats.go/jetstream"
)

func TestIngestStreamDoesNotDiscardOldMessagesWhenFull(t *testing.T) {
	config := IngestStreamConfig()
	if config.Retention != jetstream.WorkQueuePolicy || config.Discard != jetstream.DiscardNew {
		t.Fatalf("retention=%v discard=%v", config.Retention, config.Discard)
	}
	if config.MaxBytes != 25*1024*1024*1024 || config.MaxAge != 7*24*time.Hour {
		t.Fatalf("max_bytes=%d max_age=%s", config.MaxBytes, config.MaxAge)
	}
	if config.Storage != jetstream.FileStorage || config.Compression != jetstream.S2Compression {
		t.Fatalf("storage=%v compression=%v", config.Storage, config.Compression)
	}
}

func TestConsumerHasExplicitAckAndBoundedAttempts(t *testing.T) {
	config := DeliveryConsumerConfig()
	if config.AckPolicy != jetstream.AckExplicitPolicy || config.MaxDeliver != -1 {
		t.Fatalf("ack=%v max_deliver=%d", config.AckPolicy, config.MaxDeliver)
	}
	if config.FilterSubject != IngestSubjectPrefix+"*" || config.MaxAckPending != -1 || IngestStreamConfig().MaxMsgs != MaxQueuedMessages {
		t.Fatalf("filter=%q pending=%d", config.FilterSubject, config.MaxAckPending)
	}
}

func TestDeadLetterIsAllowedButBounded(t *testing.T) {
	config := DeadLetterStreamConfig()
	if config.Retention != jetstream.LimitsPolicy || config.Discard != jetstream.DiscardOld {
		t.Fatalf("retention=%v discard=%v", config.Retention, config.Discard)
	}
	if config.MaxBytes != 1024*1024*1024 || config.MaxAge != 14*24*time.Hour {
		t.Fatalf("max_bytes=%d max_age=%s", config.MaxBytes, config.MaxAge)
	}
}

func TestSanitizeReasonRemovesControlsAndTruncates(t *testing.T) {
	got := sanitizeReason("errore\n" + string(make([]byte, 200)))
	if len(got) > 160 {
		t.Fatalf("len=%d", len(got))
	}
}

func TestStreamStatsReportsDepthLimitAndOldestAge(t *testing.T) {
	now := time.Date(2026, 8, 6, 10, 0, 0, 0, time.UTC)
	info := &jetstream.StreamInfo{
		Config: jetstream.StreamConfig{Name: IngestStream, MaxBytes: 25 * 1024 * 1024 * 1024},
		State: jetstream.StreamState{
			Msgs: 1200, Bytes: 8192, FirstTime: now.Add(-4 * time.Minute),
		},
	}

	stats := streamStats(info, now)

	if stats.Name != IngestStream || stats.Messages != 1200 || stats.Bytes != 8192 {
		t.Fatalf("stats=%+v", stats)
	}
	if stats.LimitBytes != 25*1024*1024*1024 || stats.OldestAge != 4*time.Minute {
		t.Fatalf("limit=%d oldest=%s", stats.LimitBytes, stats.OldestAge)
	}
}

func TestStreamStatsDoesNotInventAnAgeOnAnEmptyStream(t *testing.T) {
	now := time.Date(2026, 8, 6, 10, 0, 0, 0, time.UTC)
	info := &jetstream.StreamInfo{
		Config: jetstream.StreamConfig{Name: IngestStream},
		State:  jetstream.StreamState{Msgs: 0},
	}

	if got := streamStats(info, now).OldestAge; got != 0 {
		t.Fatalf("oldest=%s", got)
	}
}

func TestStreamStatsDoesNotReportANegativeAgeWithSkewedClocks(t *testing.T) {
	now := time.Date(2026, 8, 6, 10, 0, 0, 0, time.UTC)
	info := &jetstream.StreamInfo{
		Config: jetstream.StreamConfig{Name: IngestStream},
		State:  jetstream.StreamState{Msgs: 3, FirstTime: now.Add(2 * time.Second)},
	}

	if got := streamStats(info, now).OldestAge; got != 0 {
		t.Fatalf("oldest=%s", got)
	}
}

func TestConsumerStatsReportsBacklogAndRedeliveries(t *testing.T) {
	info := &jetstream.ConsumerInfo{
		Stream: IngestStream, Name: DeliveryConsumer,
		NumPending: 42, NumAckPending: 7, NumRedelivered: 3,
	}

	stats := consumerStats(info)

	if stats.Stream != IngestStream || stats.Name != DeliveryConsumer {
		t.Fatalf("stats=%+v", stats)
	}
	if stats.Pending != 42 || stats.AckPending != 7 || stats.Redelivered != 3 {
		t.Fatalf("stats=%+v", stats)
	}
}

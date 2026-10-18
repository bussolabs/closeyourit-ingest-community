package natsstore

import (
	"context"
	"fmt"
	"time"

	"github.com/bussolabs/closeyourit-ingest-community/gateway/internal/queue"
	"github.com/nats-io/nats.go/jetstream"
)

// Stats takes a snapshot of the queue as JetStream sees it. The depth read
// from the broker is the only reliable one: the gateway knows what it published,
// not what the worker has already drained.
func (s *Store) Stats(ctx context.Context) (queue.StoreStats, error) {
	stats := queue.StoreStats{}
	for _, name := range []string{IngestStream, DeadLetterStream} {
		stream, err := s.js.Stream(ctx, name)
		if err != nil {
			return queue.StoreStats{}, fmt.Errorf("open stream %s: %w", name, err)
		}
		info, err := stream.Info(ctx)
		if err != nil {
			return queue.StoreStats{}, fmt.Errorf("read stream %s: %w", name, err)
		}
		stats.Streams = append(stats.Streams, streamStats(info, time.Now()))
	}
	consumerInfo, err := s.consumer.Info(ctx)
	if err != nil {
		return queue.StoreStats{}, fmt.Errorf("read consumer %s: %w", DeliveryConsumer, err)
	}
	stats.Consumers = append(stats.Consumers, consumerStats(consumerInfo))
	return stats, nil
}

func streamStats(info *jetstream.StreamInfo, now time.Time) queue.StreamStats {
	stats := queue.StreamStats{
		Name:       info.Config.Name,
		Messages:   info.State.Msgs,
		Bytes:      info.State.Bytes,
		LimitBytes: info.Config.MaxBytes,
	}
	// An empty stream keeps the FirstTime of the last drained message:
	// reading it as the backlog age would show a queue stuck for hours where there
	// is nothing left to deliver.
	if info.State.Msgs == 0 || info.State.FirstTime.IsZero() {
		return stats
	}
	if age := now.Sub(info.State.FirstTime); age > 0 {
		stats.OldestAge = age
	}
	return stats
}

func consumerStats(info *jetstream.ConsumerInfo) queue.ConsumerStats {
	return queue.ConsumerStats{
		Stream:      info.Stream,
		Name:        info.Name,
		Pending:     info.NumPending,
		AckPending:  info.NumAckPending,
		Redelivered: info.NumRedelivered,
	}
}

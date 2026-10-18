package metrics

import (
	"context"
	"time"

	"github.com/bussolabs/closeyourit-ingest-community/gateway/internal/queue"
)

const (
	// DefaultObserveInterval is tighter than the typical scrape interval: the
	// queue depth changes within seconds when the upstream goes down.
	DefaultObserveInterval = 15 * time.Second
	statsTimeout           = 5 * time.Second
)

type StatsReader interface {
	Stats(context.Context) (queue.StoreStats, error)
}

// RefreshStats updates the JetStream snapshot. Incoming traffic is not
// enough to infer the state of the queue: the worker is what drains it, and a growing
// backlog is precisely the case in which ingress says nothing.
func (r *Recorder) RefreshStats(ctx context.Context, reader StatsReader) {
	readContext, cancel := context.WithTimeout(ctx, statsTimeout)
	defer cancel()
	stats, err := reader.Stats(readContext)
	if err != nil {
		// Shutdown is not a failure: during draining the read fails
		// because of cancellation, not because JetStream is struggling.
		// The gauges stay at the last value read, so a missed read does not
		// disguise itself as an empty queue.
		if ctx.Err() == nil {
			r.statsFailures.Inc()
		}
		return
	}
	for _, stream := range stats.Streams {
		r.streamMessages.WithLabelValues(stream.Name).Set(float64(stream.Messages))
		r.streamBytes.WithLabelValues(stream.Name).Set(float64(stream.Bytes))
		r.streamLimitBytes.WithLabelValues(stream.Name).Set(float64(stream.LimitBytes))
		r.streamOldestAge.WithLabelValues(stream.Name).Set(stream.OldestAge.Seconds())
	}
	for _, consumer := range stats.Consumers {
		r.consumerPending.WithLabelValues(consumer.Stream, consumer.Name).Set(float64(consumer.Pending))
		r.consumerAck.WithLabelValues(consumer.Stream, consumer.Name).Set(float64(consumer.AckPending))
		r.consumerRedeliv.WithLabelValues(consumer.Stream, consumer.Name).Set(float64(consumer.Redelivered))
	}
}

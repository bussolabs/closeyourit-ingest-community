package chaos

import (
	"context"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/bussolabs/closeyourit-ingest-community/gateway/internal/natsstore"
)

// The real quotas of the ingest stream: capacity is measured on the harness
// but declared on these numbers, which are the server's.
const (
	ingestStreamMaxBytes = 25 * 1024 * 1024 * 1024
	ingestStreamMaxAge   = 7 * 24 * time.Hour
	rateLimitPerMinute   = 600
)

// defaultLoadRequests keeps the CI run under a minute. The real number is
// raised with INGEST_CHAOS_LOAD_REQUESTS when the measurement is needed, not on every push.
const defaultLoadRequests = 300

func TestConcurrentAuthorizedFailuresApplyBackpressureAndRecover(t *testing.T) {
	h := newHarness(t)
	requests := intFromEnv(t, "INGEST_CHAOS_LOAD_REQUESTS", defaultLoadRequests)
	const clients = 16
	h.backend.setMode(backendServerError)

	type outcome struct {
		requestID string
		status    int
	}
	results := make(chan outcome, requests)
	var senders sync.WaitGroup
	work := make(chan int, requests)
	for index := range requests {
		work <- index
	}
	close(work)

	startedAt := time.Now()
	for range clients {
		senders.Add(1)
		go func() {
			defer senders.Done()
			for index := range work {
				result, err := h.tryPost(logsPath, telemetryBody(index))
				if err != nil {
					results <- outcome{status: -1}
					continue
				}
				results <- outcome{requestID: result.RequestID, status: result.StatusCode}
			}
		}()
	}
	senders.Wait()
	close(results)
	ingestDuration := time.Since(startedAt)

	queued := make(map[string]bool, requests)
	rejected := 0
	for result := range results {
		if result.status == 503 {
			rejected++
			continue
		}
		if result.status != 202 {
			t.Fatalf("unexpected status=%d", result.status)
		}
		queued[result.requestID] = true
	}
	if len(queued) == 0 || len(queued)+rejected != requests {
		t.Fatalf("queued=%d rejected=%d requests=%d", len(queued), rejected, requests)
	}
	if depth := h.ingestDepth(); depth != uint64(len(queued)) {
		t.Fatalf("queue=%d accepted=%d", depth, len(queued))
	}

	h.backend.setMode(backendHealthy)
	h.startWorker(withConcurrency(4))
	recovery := h.waitFor(120*time.Second, "queue drain", func() bool { return h.ingestDepth() == 0 })

	delivered := deliveredRequestIDs(h.backend)
	if len(delivered) != len(queued) {
		t.Fatalf("delivered=%d accepted=%d", len(delivered), len(queued))
	}
	duplicates := 0
	for _, count := range delivered {
		if count > 1 {
			duplicates += count - 1
		}
	}
	if duplicates != 0 {
		t.Fatalf("repeated deliveries=%d with a healthy upstream", duplicates)
	}

	stream := h.streamStats(natsstore.IngestStream)
	t.Logf("load: %d accepted, %d rejected from %d clients in %s", len(queued), rejected, clients, ingestDuration.Round(time.Millisecond))
	t.Logf("recovery: %d accepted messages delivered in %s, no loss or duplicates", len(queued), recovery.Round(time.Millisecond))
	t.Logf("usage after the drain: %d bytes, %d messages", stream.Bytes, stream.Messages)
}

func TestRetryStormHonorsTheUpstreamRetryAfter(t *testing.T) {
	h := newHarness(t)
	h.backend.setMode(backendServerError)

	const messages = 5
	for index := range messages {
		if result := h.post(logsPath, telemetryBody(index)); result.StatusCode != 202 {
			t.Fatalf("request %d: status=%d", index, result.StatusCode)
		}
	}

	// The upstream is rate limited and asks for a one-second wait on every attempt:
	// the worker must obey, not retry in bursts.
	h.backend.setMode(backendRateLimited)
	h.startWorker(withConcurrency(4), withMaxAttempts(3))
	h.waitFor(90*time.Second, "isolation in dead letter", func() bool {
		return h.deadLetterDepth() == messages
	})
	h.waitFor(30*time.Second, "ingest stream drain", func() bool { return h.ingestDepth() == 0 })

	byRequest := make(map[string][]time.Time)
	for _, request := range h.backend.recorded() {
		if request.Attempt == "" {
			continue
		}
		byRequest[request.RequestID] = append(byRequest[request.RequestID], request.At)
	}
	if len(byRequest) != messages {
		t.Fatalf("retried request ids=%d, want %d", len(byRequest), messages)
	}
	for id, timestamps := range byRequest {
		if len(timestamps) > 3 {
			t.Fatalf("request id %s tried %d times beyond the limit of 3", id, len(timestamps))
		}
		sort.Slice(timestamps, func(a, b int) bool { return timestamps[a].Before(timestamps[b]) })
		for index := 1; index < len(timestamps); index++ {
			// Tolerance on the second declared by the upstream: the NAK travels and
			// the next fetch is not instantaneous, but the delay cannot
			// be shorter than the one requested.
			if gap := timestamps[index].Sub(timestamps[index-1]); gap < 900*time.Millisecond {
				t.Fatalf("request id %s retried after %s, less than the declared Retry-After", id, gap)
			}
		}
	}
	t.Logf("retry storm: %d messages, at most 3 attempts each, never closer than 1s", messages)
}

func TestBeyondTheRateLimitTheGatewayRejectsWithoutQueueing(t *testing.T) {
	const limit = 5
	h := newHarness(t, withRateLimit(limit))
	h.backend.setMode(backendServerError)

	for index := range limit {
		if result := h.post(logsPath, telemetryBody(index)); result.StatusCode != 202 {
			t.Fatalf("request %d within the limit: status=%d", index, result.StatusCode)
		}
	}

	blocked := h.post(logsPath, telemetryBody(limit))

	if blocked.StatusCode != 429 || blocked.Queued {
		t.Fatalf("over the limit: status=%d queued=%v", blocked.StatusCode, blocked.Queued)
	}
	if depth := h.ingestDepth(); depth != limit {
		t.Fatalf("queue=%d: the rejected request was queued anyway", depth)
	}

	// The rate limit must not hide the state of the service from whoever monitors it.
	if status, _ := h.get("/ready"); status != 503 {
		t.Fatalf("/ready=%d behind the rate limit", status)
	}
}

func TestBacklogCapacityAccountsForBothByteAndMessageLimits(t *testing.T) {
	h := newHarness(t)
	h.backend.setMode(backendServerError)

	const messages = 200
	for index := range messages {
		if result := h.post(logsPath, telemetryBody(index)); result.StatusCode != 202 {
			t.Fatalf("request %d: status=%d", index, result.StatusCode)
		}
	}

	stream := h.streamStats(natsstore.IngestStream)
	if stream.Messages != messages {
		t.Fatalf("queue=%d, want %d", stream.Messages, messages)
	}
	bytesPerMessage := float64(stream.Bytes) / float64(stream.Messages)
	capacityMessages := min(float64(ingestStreamMaxBytes)/bytesPerMessage, float64(natsstore.MaxQueuedMessages))
	sustainedPerSecond := capacityMessages / ingestStreamMaxAge.Seconds()

	if capacityMessages > float64(natsstore.MaxQueuedMessages) || capacityMessages <= 0 {
		t.Fatalf("invalid bounded queue capacity: %.0f", capacityMessages)
	}

	if age := stream.OldestAge; age <= 0 || age > time.Minute {
		t.Fatalf("oldest age=%s: the backlog measurement is not credible", age)
	}
	t.Logf("real usage: %.0f bytes per message on a %d byte payload", bytesPerMessage, len(telemetryBody(0)))
	t.Logf("capacity: %.0f messages in the 25 GiB of the stream, %.0f requests/s sustained for 7 days",
		capacityMessages, sustainedPerSecond)
}

func TestBeyondTheStreamExpiryMessagesDisappear(t *testing.T) {
	h := newHarness(t)
	h.backend.setMode(backendServerError)

	const messages = 10
	for index := range messages {
		if result := h.post(logsPath, telemetryBody(index)); result.StatusCode != 202 {
			t.Fatalf("request %d: status=%d", index, result.StatusCode)
		}
	}
	if depth := h.ingestDepth(); depth != messages {
		t.Fatalf("queue=%d", depth)
	}

	// The seven days of retention compressed into two seconds: what is
	// verified is that past the expiry the message leaves the stream on its own,
	// without anyone delivering it. It is the maximum loss of the ingestion
	// plane, and no alert announces it unless you watch the backlog age.
	config := natsstore.IngestStreamConfig()
	config.MaxAge = 2 * time.Second
	// The deduplication window cannot exceed the retention: compressing
	// one means compressing the other too, and the same constraint holds in production.
	config.Duplicates = time.Second
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := h.js.UpdateStream(ctx, config); err != nil {
		t.Fatalf("retention compression: %v", err)
	}

	h.waitFor(30*time.Second, "backlog expiry", func() bool { return h.ingestDepth() == 0 })

	if delivered := deliveredRequestIDs(h.backend); len(delivered) != 0 {
		t.Fatalf("delivered %d messages: the expiry is not as silent as it seems", len(delivered))
	}
	if depth := h.deadLetterDepth(); depth != 0 {
		t.Fatalf("dead letter=%d: the expiry does not go through the DLQ", depth)
	}
}

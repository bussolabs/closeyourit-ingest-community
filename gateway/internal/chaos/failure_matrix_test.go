package chaos

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bussolabs/closeyourit-ingest-community/gateway/internal/gateway"
	"github.com/bussolabs/closeyourit-ingest-community/gateway/internal/natsstore"
	"github.com/nats-io/nats.go/jetstream"
)

const logsPath = "/api/v1/projects/harness/logs"

// deliveredRequestIDs isolates deferred deliveries: only the worker marks the
// attempt, so the header tells what went through the queue apart from what
// the gateway had tried to forward directly.
func deliveredRequestIDs(backend *fakeBackend) map[string]int {
	delivered := make(map[string]int)
	for _, request := range backend.recorded() {
		if request.Attempt != "" {
			delivered[request.RequestID]++
		}
	}
	return delivered
}

func TestAuthorizedUpstreamFailureQueuesAndRecoversWithoutDuplicates(t *testing.T) {
	h := newHarness(t)
	h.backend.setMode(backendServerError)

	const messages = 25
	queued := make(map[string]bool, messages)
	for index := range messages {
		result := h.post(logsPath, telemetryBody(index))
		if result.StatusCode != 202 || !result.Queued || result.RequestID == "" {
			t.Fatalf("request %d: status=%d queued=%v id=%q", index, result.StatusCode, result.Queued, result.RequestID)
		}
		queued[result.RequestID] = true
	}
	if len(queued) != messages {
		t.Fatalf("distinct request ids=%d, want %d", len(queued), messages)
	}
	if depth := h.ingestDepth(); depth != messages {
		t.Fatalf("queue=%d, want %d stored messages", depth, messages)
	}

	h.backend.setMode(backendHealthy)
	h.startWorker()
	recovery := h.waitFor(60*time.Second, "queue drain", func() bool { return h.ingestDepth() == 0 })

	delivered := deliveredRequestIDs(h.backend)
	if len(delivered) != messages {
		t.Fatalf("delivered %d distinct request ids, want %d", len(delivered), messages)
	}
	for id, count := range delivered {
		if !queued[id] {
			t.Fatalf("delivered a request id never queued: %s", id)
		}
		if count != 1 {
			t.Fatalf("request id %s delivered %d times with a healthy upstream", id, count)
		}
	}
	if depth := h.deadLetterDepth(); depth != 0 {
		t.Fatalf("dead letter=%d after a successful recovery", depth)
	}
	t.Logf("RTO with %d messages queued and the upstream healthy again: %s", messages, recovery.Round(time.Millisecond))
}

func TestAuthorizedFailuresQueueTelemetryButNotRawDiagnostics(t *testing.T) {
	h := newHarness(t)
	h.backend.setMode(backendServerError)

	result := h.post(logsPath, telemetryBody(1))

	if result.StatusCode != 202 {
		t.Fatalf("status=%d body=%s", result.StatusCode, result.Body)
	}
	if !result.Queued || result.RequestID == "" {
		t.Fatalf("queueing headers missing: queued=%v id=%q", result.Queued, result.RequestID)
	}
	if !strings.Contains(result.Body, `"queued":true`) {
		t.Fatalf("body=%s", result.Body)
	}
	if depth := h.ingestDepth(); depth != 1 {
		t.Fatalf("queue=%d", depth)
	}

	// Raw diagnostic data must remain with the client until admission succeeds.
	for _, path := range []string{"/api/harness/envelope", "/api/harness/minidump"} {
		raw := h.post(path, telemetryBody(2))
		if raw.StatusCode != http.StatusServiceUnavailable || raw.Queued {
			t.Fatalf("%s status=%d queued=%v", path, raw.StatusCode, raw.Queued)
		}
		if depth := h.ingestDepth(); depth != 1 {
			t.Fatalf("raw diagnostics changed queue depth to %d", depth)
		}
	}
}

func TestUpstreamTimeoutRejectsWithoutAuthorization(t *testing.T) {
	h := newHarness(t)
	// The gateway grants 3 seconds to direct forwarding: beyond that, a Rails
	// that answers anyway cannot be told apart from a stopped one, and keeping the
	// client hanging helps nobody.
	h.backend.setLatency(5 * time.Second)

	startedAt := time.Now()
	result := h.post(logsPath, telemetryBody(1))
	elapsed := time.Since(startedAt)

	if result.StatusCode != 503 || result.Queued {
		t.Fatalf("status=%d queued=%v body=%s", result.StatusCode, result.Queued, result.Body)
	}
	if elapsed >= 5*time.Second {
		t.Fatalf("the gateway waited %s: the forwarding timeout did not cut in", elapsed)
	}
	if depth := h.ingestDepth(); depth != 0 {
		t.Fatalf("queue=%d", depth)
	}
	t.Logf("upstream at 5s latency: client receives 503 after %s", elapsed.Round(100*time.Millisecond))
}

func TestUnavailableQueuePromisesNoMoreThanItKeeps(t *testing.T) {
	h := newHarness(t)
	h.backend.setMode(backendServerError)
	h.stopNATS()
	h.waitFor(20*time.Second, "disconnection from NATS", func() bool { return !h.connection.IsConnected() })

	// With the upstream answering, the client gets CloseYourIt's real
	// response: no promise of retention.
	withUpstream := h.post(logsPath, telemetryBody(1))
	if withUpstream.StatusCode != 503 || withUpstream.Queued {
		t.Fatalf("status=%d queued=%v", withUpstream.StatusCode, withUpstream.Queued)
	}
	if strings.Contains(withUpstream.Body, "queued") {
		t.Fatalf("the gateway claims it queued without a queue: %s", withUpstream.Body)
	}

	// Without upstream and without queue there is nothing left to do but say so.
	h.backend.setMode(backendNetworkDrop)
	startedAt := time.Now()
	withoutUpstream := h.post(logsPath, telemetryBody(2))
	blockedFor := time.Since(startedAt)
	if withoutUpstream.StatusCode != 503 || withoutUpstream.Queued {
		t.Fatalf("status=%d queued=%v", withoutUpstream.StatusCode, withoutUpstream.Queued)
	}
	// Publishing without a broker waits for its own timeout: the client stays
	// hanging for that whole window. It must stay below the gateway's WriteTimeout,
	// otherwise the client gets a truncation instead of a readable
	// error.
	if blockedFor >= 20*time.Second {
		t.Fatalf("request blocked for %s with the queue down", blockedFor)
	}
	t.Logf("with the queue down the client waits %s before the rejection", blockedFor.Round(100*time.Millisecond))
	if !strings.Contains(withoutUpstream.Body, "R503-INGEST-GATEWAY-004") {
		t.Fatalf("body=%s", withoutUpstream.Body)
	}

	status, payload := h.get("/ready")
	if status != 503 || !strings.Contains(payload, `"status":"unavailable"`) {
		t.Fatalf("/ready status=%d payload=%s", status, payload)
	}
	if !strings.Contains(payload, `"accepting":false`) {
		t.Fatalf("/ready does not declare it stopped accepting: %s", payload)
	}

	if liveness, _ := h.get("/up"); liveness != 200 {
		t.Fatalf("/up=%d: liveness must not depend on the queue", liveness)
	}
}

func TestFullStreamQuotaRejectsNewMessagesWithoutTouchingOldOnes(t *testing.T) {
	h := newHarness(t)
	h.shrinkIngestStream(512 * 1024)
	h.backend.setMode(backendServerError)

	body := payloadOfSize(64 * 1024)
	accepted, rejected := 0, 0
	var firstRejection postResult
	for range 20 {
		result := h.post(logsPath, body)
		switch result.StatusCode {
		case 202:
			accepted++
		case 503:
			if rejected == 0 {
				firstRejection = result
			}
			rejected++
		default:
			t.Fatalf("unexpected status=%d body=%s", result.StatusCode, result.Body)
		}
	}

	if accepted == 0 || rejected == 0 {
		t.Fatalf("accepted=%d rejected=%d: the quota did not apply backpressure", accepted, rejected)
	}
	if firstRejection.Queued || !strings.Contains(firstRejection.Body, "R503-CLOSEYOURIT-001") {
		t.Fatalf("the rejection is not explicit: queued=%v body=%s", firstRejection.Queued, firstRejection.Body)
	}

	// DiscardNew: what was already queued stays, the new one is rejected.
	if depth := h.ingestDepth(); depth != uint64(accepted) {
		t.Fatalf("queue=%d, queued=%d: the quota discarded old messages", depth, accepted)
	}
	t.Logf("512 KiB quota with 64 KiB payloads: %d queued, %d rejected", accepted, rejected)
}

func TestSetupRefusesToStartWhenTheDiskDoesNotCoverTheDeclaredQuotas(t *testing.T) {
	if testing.Short() {
		t.Skip("the load and failure suite starts NATS: skipped with -short")
	}
	// 64 MiB are not enough for the 25 GiB of the ingest stream: the gateway must
	// stop at startup, not accept traffic it will not be able to keep.
	port := freePort(t)
	natsServer := startNATSServer(t, t.TempDir(), port, 64*1024*1024)
	defer func() {
		natsServer.Shutdown()
		natsServer.WaitForShutdown()
	}()
	connection, js := connectNATS(t, port)
	defer connection.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_, err := natsstore.Setup(ctx, js)

	if err == nil {
		t.Fatal("setup succeeded on a disk that does not cover the declared quotas")
	}
	if !strings.Contains(err.Error(), "configure ingest stream") {
		t.Fatalf("error not explicit enough: %v", err)
	}
}

func TestNATSRestartKeepsAcknowledgedMessages(t *testing.T) {
	h := newHarness(t)
	h.backend.setMode(backendServerError)

	const messages = 20
	queued := make(map[string]bool, messages)
	for index := range messages {
		result := h.post(logsPath, telemetryBody(index))
		if result.StatusCode != 202 {
			t.Fatalf("request %d: status=%d", index, result.StatusCode)
		}
		queued[result.RequestID] = true
	}

	h.restartNATS()

	// RPO: what the broker acknowledged survives the restart, whole.
	if depth := h.ingestDepth(); depth != messages {
		t.Fatalf("after the restart the queue has %d messages, want %d", depth, messages)
	}

	h.backend.setMode(backendHealthy)
	h.startWorker()
	recovery := h.waitFor(60*time.Second, "drain after the restart", func() bool { return h.ingestDepth() == 0 })

	delivered := deliveredRequestIDs(h.backend)
	if len(delivered) != messages {
		t.Fatalf("delivered %d request ids, want %d", len(delivered), messages)
	}
	for id := range delivered {
		if !queued[id] {
			t.Fatalf("request id %s was not among those queued before the restart", id)
		}
	}
	t.Logf("NATS restart: RPO 0 on %d acknowledged messages, RTO %s", messages, recovery.Round(time.Millisecond))
}

func TestGatewayRestartLeavesNoGapsOrDuplicates(t *testing.T) {
	h := newHarness(t)
	h.backend.setMode(backendServerError)

	var mu sync.Mutex
	accepted := make(map[string]bool)
	stop := make(chan struct{})
	var traffic sync.WaitGroup
	traffic.Add(1)
	go func() {
		defer traffic.Done()
		for index := 0; ; index++ {
			select {
			case <-stop:
				return
			default:
			}
			result, err := h.tryPost(logsPath, telemetryBody(index))
			// Requests in flight during the restart fail: it is the case in
			// which the client does not know and retries. Only the 202s count, because they are
			// the only ones for which the gateway promised something.
			if err != nil || result.StatusCode != 202 {
				continue
			}
			mu.Lock()
			accepted[result.RequestID] = true
			mu.Unlock()
		}
	}()

	h.waitFor(30*time.Second, "first queued traffic", func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(accepted) >= 10
	})
	h.restartGateway()
	h.waitFor(30*time.Second, "traffic queued after the restart", func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(accepted) >= 25
	})
	close(stop)
	traffic.Wait()

	mu.Lock()
	promised := len(accepted)
	mu.Unlock()
	if depth := h.ingestDepth(); depth != uint64(promised) {
		t.Fatalf("queue=%d, promised 202s=%d: the restart left a gap or a duplicate", depth, promised)
	}
	t.Logf("gateway restart during traffic: %d requests queued, no gap", promised)
}

func TestWorkerRestartBeforeAckRedeliversTheSameRequestID(t *testing.T) {
	h := newHarness(t)
	h.compressAckWait(time.Second)
	h.backend.setMode(backendServerError)

	queued := h.post(logsPath, telemetryBody(1))
	if queued.StatusCode != 202 {
		t.Fatalf("status=%d", queued.StatusCode)
	}
	h.backend.setMode(backendHealthy)

	// The worker delivers to CloseYourIt and dies before acknowledging: the broker
	// does not know the work was done and will put it back into circulation.
	consumer := &interceptingConsumer{inner: h.store}
	consumer.swallowAck.Store(true)
	crashing := h.startWorker(withConsumer(consumer), withConcurrency(1))
	h.waitFor(30*time.Second, "first delivery", func() bool { return len(deliveredRequestIDs(h.backend)) == 1 })
	crashing.stop()

	consumer.swallowAck.Store(false)
	h.startWorker(withConsumer(consumer), withConcurrency(1))
	h.waitFor(60*time.Second, "redelivery and acknowledgement", func() bool { return h.ingestDepth() == 0 })

	delivered := deliveredRequestIDs(h.backend)
	if len(delivered) != 1 {
		t.Fatalf("distinct request ids delivered=%d, want 1", len(delivered))
	}
	if count := delivered[queued.RequestID]; count < 2 {
		t.Fatalf("deliveries of the same request id=%d: the redelivery did not happen", count)
	}

	// The second delivery is recognizable: same request id and a higher attempt
	// number than the first. It is the information CloseYourIt
	// deduplicates on. The numbers are not necessarily consecutive: a round may have
	// been redelivered without reaching its destination.
	var attempts []int
	for _, request := range h.backend.recorded() {
		if request.Attempt == "" {
			continue
		}
		attempt, err := strconv.Atoi(request.Attempt)
		if err != nil {
			t.Fatalf("unreadable attempt number: %q", request.Attempt)
		}
		attempts = append(attempts, attempt)
	}
	if len(attempts) < 2 || attempts[0] != 1 || attempts[len(attempts)-1] <= attempts[0] {
		t.Fatalf("observed attempts=%v: the duplicate cannot be told apart", attempts)
	}
	t.Logf("restart before the ACK: %d deliveries of the same request id, deduplicable by the backend", delivered[queued.RequestID])
}

func TestWorkerRestartAfterDeadLetterDoesNotDuplicateInTheDLQ(t *testing.T) {
	h := newHarness(t)
	h.compressAckWait(time.Second)
	h.backend.setMode(backendServerError)

	if result := h.post(logsPath, telemetryBody(3)); result.StatusCode != 202 {
		t.Fatalf("status=%d", result.StatusCode)
	}

	// Definitive refusal: the message must be isolated at the first attempt.
	h.backend.setMode(backendPermanentError)
	consumer := &interceptingConsumer{inner: h.store}
	consumer.swallowAck.Store(true)
	crashing := h.startWorker(withConsumer(consumer), withConcurrency(1))
	h.waitFor(30*time.Second, "first dead letter", func() bool { return h.deadLetterDepth() == 1 })
	crashing.stop()

	consumer.swallowAck.Store(false)
	h.startWorker(withConsumer(consumer), withConcurrency(1))
	h.waitFor(60*time.Second, "acknowledgement after the redelivery", func() bool { return h.ingestDepth() == 0 })

	if depth := h.deadLetterDepth(); depth != 1 {
		t.Fatalf("dead letter=%d: the republication duplicated", depth)
	}
	if consumer.delivered.Load() < 2 {
		t.Fatalf("deliveries to the worker=%d: the message was not redelivered", consumer.delivered.Load())
	}
}

func TestTooManyAttemptsEndInDeadLetterAndFreeTheStream(t *testing.T) {
	h := newHarness(t)
	h.backend.setMode(backendServerError)
	if result := h.post(logsPath, telemetryBody(4)); result.StatusCode != 202 {
		t.Fatalf("status=%d", result.StatusCode)
	}

	h.backend.setMode(backendRateLimited)
	h.startWorker(withConcurrency(1), withMaxAttempts(3))
	h.waitFor(60*time.Second, "isolation in dead letter", func() bool { return h.deadLetterDepth() == 1 })

	// Cleanup: the isolated message does not also stay in the ingest stream,
	// otherwise the queue would never get back to zero.
	h.waitFor(30*time.Second, "ingest stream drain", func() bool { return h.ingestDepth() == 0 })

	attempts := deliveredRequestIDs(h.backend)
	for id, count := range attempts {
		if count > 3 {
			t.Fatalf("request id %s tried %d times, beyond the limit of 3", id, count)
		}
	}
}

func TestFiveMebibytePayloadCrossesTheQueueIntact(t *testing.T) {
	h := newHarness(t)
	h.backend.setMode(backendServerError)

	body := payloadOfSize(int(gateway.DefaultMaxBodyBytes))
	expected := sha256.Sum256(body)
	queued := h.post(logsPath, body)
	if queued.StatusCode != 202 || !queued.Queued {
		t.Fatalf("status=%d queued=%v body=%s", queued.StatusCode, queued.Queued, queued.Body)
	}
	if depth := h.ingestDepth(); depth != 1 {
		t.Fatalf("queue=%d: the maximum payload was not stored", depth)
	}

	oversized := h.post(logsPath, payloadOfSize(int(gateway.DefaultMaxBodyBytes)+1))
	if oversized.StatusCode != 413 || oversized.Queued {
		t.Fatalf("over the limit: status=%d queued=%v", oversized.StatusCode, oversized.Queued)
	}
	if depth := h.ingestDepth(); depth != 1 {
		t.Fatalf("queue=%d: the rejected payload was queued anyway", depth)
	}

	h.backend.setMode(backendHealthy)
	h.startWorker(withConcurrency(1))
	h.waitFor(60*time.Second, "delivery of the maximum payload", func() bool { return h.ingestDepth() == 0 })

	var restored recordedRequest
	for _, request := range h.backend.recorded() {
		if request.Attempt != "" {
			restored = request
		}
	}
	if restored.BodyBytes != len(body) || restored.BodySum != hex.EncodeToString(expected[:]) {
		t.Fatalf("delivered payload: %d bytes, sha=%s", restored.BodyBytes, restored.BodySum)
	}
	t.Logf("%d byte payload stored encrypted and redelivered identical", len(body))
}

func TestIngestStreamStaysWithinTheJetStreamMaximum(t *testing.T) {
	h := newHarness(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	stream, err := h.js.Stream(ctx, natsstore.IngestStream)
	if err != nil {
		t.Fatalf("opening stream: %v", err)
	}
	info, err := stream.Info(ctx)
	if err != nil {
		t.Fatalf("stream state: %v", err)
	}

	// The largest message accepted by the gateway must fit within the limits that
	// stream and broker declare, otherwise the 202 is a lie discovered only
	// by the maximum payload.
	if info.Config.MaxMsgSize < int32(gateway.DefaultMaxBodyBytes) {
		t.Fatalf("max_msg_size=%d, maximum body=%d", info.Config.MaxMsgSize, gateway.DefaultMaxBodyBytes)
	}
	varz, err := h.natsServer.Varz(nil)
	if err != nil {
		t.Fatalf("broker state: %v", err)
	}
	if int64(varz.MaxPayload) < gateway.DefaultMaxBodyBytes {
		t.Fatalf("max_payload=%d, maximum body=%d", varz.MaxPayload, gateway.DefaultMaxBodyBytes)
	}
	if info.Config.Discard != jetstream.DiscardNew || info.Config.Retention != jetstream.WorkQueuePolicy {
		t.Fatalf("discard=%v retention=%v", info.Config.Discard, info.Config.Retention)
	}
}

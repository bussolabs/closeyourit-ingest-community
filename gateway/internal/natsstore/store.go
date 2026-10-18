package natsstore

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/bussolabs/closeyourit-ingest-community/gateway/internal/queue"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

const (
	IngestStream     = "CYI_INGEST"
	DeadLetterStream = "CYI_INGEST_DLQ"
	DeliveryConsumer = "delivery-v1"
	// A 256 MiB pending-state budget, reserving at least 1 KiB per message.
	MaxQueuedMessages       = 250000
	IngestSubjectPrefix     = "cyi.ingest.v1."
	DeadLetterSubjectPrefix = "cyi.ingest.dlq.v1."
)

type Store struct {
	js       jetstream.JetStream
	consumer jetstream.Consumer
}

func Setup(ctx context.Context, js jetstream.JetStream) (*Store, error) {
	config := IngestStreamConfig()
	requested := strings.TrimSpace(os.Getenv("QUEUE_MAX_MESSAGES"))
	if requested != "" {
		limit, err := strconv.ParseInt(requested, 10, 64)
		if err != nil || limit <= 0 {
			return nil, fmt.Errorf("QUEUE_MAX_MESSAGES must be a positive integer")
		}
		config.MaxMsgs = limit
	}
	// Refuse a limit reduction that could discard an existing backlog during an upgrade.
	if stream, err := js.Stream(ctx, IngestStream); err == nil {
		info, infoErr := stream.Info(ctx)
		if infoErr != nil {
			return nil, fmt.Errorf("inspect existing ingest stream: %w", infoErr)
		}
		if requested == "" && info.Config.MaxMsgs > 0 {
			config.MaxMsgs = info.Config.MaxMsgs
		}
		if info.Config.MaxMsgs <= 0 || info.Config.MaxMsgs > config.MaxMsgs {
			return nil, fmt.Errorf("existing ingest stream requires an explicit migration to MaxMsgs=%d before upgrading; pause publishers before reducing the limit", config.MaxMsgs)
		}
	} else if !errors.Is(err, jetstream.ErrStreamNotFound) {
		return nil, fmt.Errorf("inspect ingest stream: %w", err)
	}
	if _, err := js.CreateOrUpdateStream(ctx, config); err != nil {
		return nil, fmt.Errorf("configure ingest stream: %w", err)
	}
	if _, err := js.CreateOrUpdateStream(ctx, DeadLetterStreamConfig()); err != nil {
		return nil, fmt.Errorf("configure dead-letter stream: %w", err)
	}
	consumer, err := js.CreateOrUpdateConsumer(ctx, IngestStream, DeliveryConsumerConfig())
	if err != nil {
		return nil, fmt.Errorf("configure delivery consumer: %w", err)
	}
	return &Store{js: js, consumer: consumer}, nil
}

// DefaultIngestMaxBytes is the queue size of the production gateway. A self-hosted install on a
// small disk lowers it with QUEUE_MAX_BYTES (CYRA-919): NATS refuses a stream larger than its store.
const DefaultIngestMaxBytes int64 = 25 * 1024 * 1024 * 1024

func ingestMaxBytes() int64 {
	if value, err := strconv.ParseInt(strings.TrimSpace(os.Getenv("QUEUE_MAX_BYTES")), 10, 64); err == nil && value > 0 {
		return value
	}
	return DefaultIngestMaxBytes
}

func IngestStreamConfig() jetstream.StreamConfig {
	return jetstream.StreamConfig{
		Name: IngestStream, Description: "Richieste CloseYourIt in attesa di delivery",
		Subjects: []string{IngestSubjectPrefix + "*"}, Retention: jetstream.WorkQueuePolicy,
		MaxConsumers: 1, MaxMsgs: MaxQueuedMessages, MaxBytes: ingestMaxBytes(), MaxAge: 7 * 24 * time.Hour,
		MaxMsgSize: 6 * 1024 * 1024, Storage: jetstream.FileStorage, Replicas: 1,
		Discard: jetstream.DiscardNew, Duplicates: 10 * time.Minute, Compression: jetstream.S2Compression,
	}
}

func DeadLetterStreamConfig() jetstream.StreamConfig {
	return jetstream.StreamConfig{
		Name: DeadLetterStream, Description: "CloseYourIt requests that could not be delivered",
		Subjects: []string{DeadLetterSubjectPrefix + "*"}, Retention: jetstream.LimitsPolicy,
		MaxBytes: 1024 * 1024 * 1024, MaxAge: 14 * 24 * time.Hour,
		MaxMsgSize: 6 * 1024 * 1024, Storage: jetstream.FileStorage, Replicas: 1,
		Discard: jetstream.DiscardOld, Duplicates: 10 * time.Minute, Compression: jetstream.S2Compression,
	}
}

func DeliveryConsumerConfig() jetstream.ConsumerConfig {
	return jetstream.ConsumerConfig{
		Name: DeliveryConsumer, Durable: DeliveryConsumer, Description: "Delivery HTTP verso CloseYourIt",
		// MaxDeliver stays unlimited at broker level: from the twentieth attempt the
		// worker no longer calls Rails and moves to the DLQ. If it dies during that step,
		// JetStream must be able to hand it out again until the DLQ and the ACK succeed atomically.
		AckPolicy: jetstream.AckExplicitPolicy, AckWait: 30 * time.Second, MaxDeliver: -1,
		// Delayed retries must not block unrelated messages; stream count bounds pending metadata.
		FilterSubject: IngestSubjectPrefix + "*", MaxAckPending: -1, Replicas: 1,
	}
}

func (s *Store) Publish(ctx context.Context, message queue.Message) error {
	_, err := s.js.Publish(ctx, IngestSubjectPrefix+message.Kind, message.Ciphertext,
		jetstream.WithMsgID(message.ID), jetstream.WithExpectStream(IngestStream))
	if err != nil {
		return fmt.Errorf("publish ingest: %w", err)
	}
	return nil
}

func (s *Store) DeadLetter(ctx context.Context, message queue.Message, reason string) error {
	natsMessage := nats.NewMsg(DeadLetterSubjectPrefix + message.Kind)
	natsMessage.Data = message.Ciphertext
	natsMessage.Header.Set("X-CloseYourIt-Request-Id", message.ID)
	natsMessage.Header.Set("X-CloseYourIt-Dead-Letter-Reason", sanitizeReason(reason))
	if _, err := s.js.PublishMsg(ctx, natsMessage,
		jetstream.WithMsgID("dlq-"+message.ID), jetstream.WithExpectStream(DeadLetterStream)); err != nil {
		return fmt.Errorf("publish dead letter: %w", err)
	}
	return nil
}

func (s *Store) Next(ctx context.Context) (*queue.Delivery, error) {
	batch, err := s.consumer.Fetch(1, jetstream.FetchMaxWait(2*time.Second))
	if err != nil {
		return nil, fmt.Errorf("fetch delivery: %w", err)
	}
	for message := range batch.Messages() {
		metadata, err := message.Metadata()
		if err != nil {
			return nil, fmt.Errorf("read delivery metadata: %w", err)
		}
		kind := strings.TrimPrefix(message.Subject(), IngestSubjectPrefix)
		id := message.Headers().Get("Nats-Msg-Id")
		if id == "" {
			id = fmt.Sprintf("stream-%d", metadata.Sequence.Stream)
		}
		return &queue.Delivery{
			ID: id, Kind: kind, Ciphertext: append([]byte(nil), message.Data()...), Attempts: metadata.NumDelivered,
			Ack: message.DoubleAck, Retry: message.NakWithDelay,
		}, nil
	}
	if err := batch.Error(); err != nil && !errors.Is(err, context.DeadlineExceeded) && !errors.Is(err, nats.ErrTimeout) {
		return nil, fmt.Errorf("fetch delivery batch: %w", err)
	}
	return nil, queue.ErrNoMessage
}

func sanitizeReason(reason string) string {
	reason = strings.Map(func(r rune) rune {
		if r < 32 || r > 126 {
			return -1
		}
		return r
	}, reason)
	if len(reason) > 160 {
		reason = reason[:160]
	}
	return reason
}

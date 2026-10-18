package natsstore

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/bussolabs/closeyourit-ingest-community/gateway/internal/queue"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

func isolatedJetStream(t *testing.T) jetstream.JetStream {
	t.Helper()
	// Stream reservations do not allocate disk; the enclosing sandbox bounds actual writes.
	s, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1, JetStream: true, StoreDir: t.TempDir(), JetStreamMaxStore: 2 * 1024 * 1024 * 1024})
	if err != nil {
		t.Fatal(err)
	}
	s.Start()
	t.Cleanup(s.Shutdown)
	if !s.ReadyForConnections(5 * time.Second) {
		t.Fatal("NATS did not start")
	}
	nc, err := nats.Connect(s.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(nc.Close)
	js, err := jetstream.New(nc)
	if err != nil {
		t.Fatal(err)
	}
	return js
}

func TestDelayedRetriesDoNotBlockUnrelatedMessages(t *testing.T) {
	t.Setenv("QUEUE_MAX_BYTES", "16777216")
	js := isolatedJetStream(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	store, err := Setup(ctx, js)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 32; i++ {
		if err := store.Publish(ctx, queue.Message{ID: fmt.Sprint(i), Kind: "events", Ciphertext: []byte("delayed")}); err != nil {
			t.Fatal(err)
		}
		message, err := store.Next(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if err := message.Retry(time.Minute); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.Publish(ctx, queue.Message{ID: "unrelated", Kind: "logs", Ciphertext: []byte("ready")}); err != nil {
		t.Fatal(err)
	}
	message, err := store.Next(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if message.ID != "unrelated" {
		t.Fatalf("delivered %q instead of unrelated message", message.ID)
	}
	if err := message.Ack(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestSetupRefusesAnUnmigratedStreamWithoutChangingItsBacklog(t *testing.T) {
	t.Setenv("QUEUE_MAX_BYTES", "16777216")
	js := isolatedJetStream(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	config := IngestStreamConfig()
	config.MaxMsgs = -1
	stream, err := js.CreateStream(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := js.Publish(ctx, IngestSubjectPrefix+"events", []byte("preserve")); err != nil {
		t.Fatal(err)
	}
	if _, err := Setup(ctx, js); err == nil {
		t.Fatal("unmigrated stream accepted")
	}
	info, err := stream.Info(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if info.Config.MaxMsgs != -1 || info.State.Msgs != 1 {
		t.Fatalf("stream changed: %+v", info)
	}
}

func TestSetupPreservesExistingCapacityUnlessExplicitlyConfigured(t *testing.T) {
	t.Setenv("QUEUE_MAX_BYTES", "16777216")
	t.Setenv("QUEUE_MAX_MESSAGES", "")
	js := isolatedJetStream(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	config := IngestStreamConfig()
	config.MaxMsgs = 500000
	stream, err := js.CreateStream(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Setup(ctx, js); err != nil {
		t.Fatal(err)
	}
	info, err := stream.Info(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if info.Config.MaxMsgs != 500000 {
		t.Fatalf("existing capacity changed: %d", info.Config.MaxMsgs)
	}
	t.Setenv("QUEUE_MAX_MESSAGES", "750000")
	if _, err := Setup(ctx, js); err != nil {
		t.Fatal(err)
	}
	info, err = stream.Info(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if info.Config.MaxMsgs != 750000 {
		t.Fatalf("explicit increase ignored: %d", info.Config.MaxMsgs)
	}
	t.Setenv("QUEUE_MAX_MESSAGES", "250000")
	if _, err := Setup(ctx, js); err == nil {
		t.Fatal("capacity reduction must require controlled migration")
	}
}

func TestSetupRejectsInvalidCapacityBeforeContactingNATS(t *testing.T) {
	for _, value := range []string{"0", "-1", "bad", "99999999999999999999999"} {
		t.Run(value, func(t *testing.T) {
			t.Setenv("QUEUE_MAX_MESSAGES", value)
			if _, err := Setup(context.Background(), nil); err == nil {
				t.Fatal("invalid capacity accepted")
			}
		})
	}
}

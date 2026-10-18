package queue

import (
	"context"
	"errors"
	"time"
)

var ErrNoMessage = errors.New("no message available")

type Message struct {
	ID         string
	Kind       string
	Ciphertext []byte
}

type Publisher interface {
	Publish(context.Context, Message) error
}

type Delivery struct {
	ID         string
	Kind       string
	Ciphertext []byte
	Attempts   uint64
	Ack        func(context.Context) error
	Retry      func(time.Duration) error
}

type Consumer interface {
	Next(context.Context) (*Delivery, error)
}

type DeadLetterPublisher interface {
	DeadLetter(context.Context, Message, string) error
}

// StreamStats and ConsumerStats are the snapshot needed to understand whether the queue
// is growing: the package that reads them must not know JetStream, and whoever
// publishes them must not know the metrics format.
type StreamStats struct {
	Name       string
	Messages   uint64
	Bytes      uint64
	LimitBytes int64
	// OldestAge is the age of the oldest message still in the queue, 0 if the
	// stream is empty: it is the signal that tells how long until the backlog
	// expires, which depth alone does not reveal.
	OldestAge time.Duration
}

type ConsumerStats struct {
	Stream      string
	Name        string
	Pending     uint64
	AckPending  int
	Redelivered int
}

type StoreStats struct {
	Streams   []StreamStats
	Consumers []ConsumerStats
}

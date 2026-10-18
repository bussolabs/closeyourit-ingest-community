// Package chaos is the load and failure harness of the ingest gateway.
//
// It mounts in-process the same pieces that run on the server — NATS with the
// real configuration, the gateway, the delivery worker — and runs controlled
// traffic and failures over them: unreachable upstream, full queue, exhausted
// disk, restarts in the middle of publish, ACK and dead letter. It serves to
// measure capacity, maximum loss and recovery time before the clients are the
// ones to discover them, without touching anything production-like.
//
// Everything lives in _test.go files: the harness does not enter the gateway binary.
// The scenario matrix and the measured numbers are in
// docs/runbooks/ingest-load-chaos.md.
package chaos

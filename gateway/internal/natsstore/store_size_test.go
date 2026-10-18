package natsstore

import "testing"

func TestIngestQueueKeepsTheProductionSizeByDefault(t *testing.T) {
	t.Setenv("QUEUE_MAX_BYTES", "")

	if got := IngestStreamConfig().MaxBytes; got != DefaultIngestMaxBytes {
		t.Fatalf("max bytes = %d, want %d", got, DefaultIngestMaxBytes)
	}
}

func TestIngestQueueSizeComesFromTheEnvironment(t *testing.T) {
	t.Setenv("QUEUE_MAX_BYTES", "4294967296")

	if got := IngestStreamConfig().MaxBytes; got != 4294967296 {
		t.Fatalf("max bytes = %d, want 4294967296", got)
	}
}

func TestIngestQueueIgnoresAnUnreadableSize(t *testing.T) {
	t.Setenv("QUEUE_MAX_BYTES", "four gigabytes")

	if got := IngestStreamConfig().MaxBytes; got != DefaultIngestMaxBytes {
		t.Fatalf("max bytes = %d, want %d", got, DefaultIngestMaxBytes)
	}
}

package envelope

import (
	"bytes"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestEncodeDecodePreservesBinaryRequest(t *testing.T) {
	now := time.Date(2026, 7, 12, 5, 0, 0, 123, time.UTC)
	original := Request{
		Method: "POST", Path: "/api/project/envelope", RawQuery: "sentry_key=abc",
		Headers:    map[string]string{"Content-Encoding": "gzip", "Authorization": "Bearer secret"},
		RemoteAddr: "203.0.113.10", ReceivedAt: now, Body: []byte{0x1f, 0x8b, 0x00, 0xff},
	}

	encoded, err := Encode(original)
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}
	decoded, err := Decode(encoded)
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}
	if decoded.Method != original.Method || decoded.Path != original.Path || decoded.RawQuery != original.RawQuery {
		t.Fatalf("metadata differs: %#v", decoded)
	}
	if decoded.Headers["Authorization"] != "Bearer secret" || decoded.RemoteAddr != original.RemoteAddr {
		t.Fatalf("headers or address not preserved: %#v", decoded)
	}
	if !decoded.ReceivedAt.Equal(now) || !bytes.Equal(decoded.Body, original.Body) {
		t.Fatalf("time or body not preserved: %#v", decoded)
	}
}

func TestDecodeRejectsTruncatedEnvelope(t *testing.T) {
	if _, err := Decode([]byte{0, 0, 1}); !errors.Is(err, ErrInvalidEnvelope) {
		t.Fatalf("Decode() error = %v, want ErrInvalidEnvelope", err)
	}
}

func TestEncodeRejectsMetadataBeyondTheLimit(t *testing.T) {
	_, err := Encode(Request{
		Method: "POST", Path: "/api/v1/projects/p/events", ReceivedAt: time.Now(),
		Headers: map[string]string{"X-Large": strings.Repeat("x", maxMetadataBytes)},
	})
	if !errors.Is(err, ErrMetadataTooLarge) {
		t.Fatalf("Encode() error = %v, want ErrMetadataTooLarge", err)
	}
}

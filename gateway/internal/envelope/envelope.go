package envelope

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

const maxMetadataBytes = 64 * 1024

var (
	ErrInvalidEnvelope  = errors.New("invalid envelope")
	ErrMetadataTooLarge = errors.New("envelope metadata too large")
)

// Request is the binary contract persisted in JetStream. The body stays raw:
// gzip, Sentry envelopes and JSON are delivered without reinterpretation.
type Request struct {
	Method     string            `json:"method"`
	Path       string            `json:"path"`
	RawQuery   string            `json:"raw_query,omitempty"`
	Headers    map[string]string `json:"headers,omitempty"`
	RemoteAddr string            `json:"remote_addr,omitempty"`
	ReceivedAt time.Time         `json:"received_at"`
	Body       []byte            `json:"-"`
}

type metadata struct {
	Method     string            `json:"method"`
	Path       string            `json:"path"`
	RawQuery   string            `json:"raw_query,omitempty"`
	Headers    map[string]string `json:"headers,omitempty"`
	RemoteAddr string            `json:"remote_addr,omitempty"`
	ReceivedAt time.Time         `json:"received_at"`
}

func Encode(request Request) ([]byte, error) {
	meta, err := json.Marshal(metadata{
		Method: request.Method, Path: request.Path, RawQuery: request.RawQuery,
		Headers: request.Headers, RemoteAddr: request.RemoteAddr, ReceivedAt: request.ReceivedAt,
	})
	if err != nil {
		return nil, fmt.Errorf("encode metadata: %w", err)
	}
	if len(meta) > maxMetadataBytes {
		return nil, ErrMetadataTooLarge
	}

	encoded := make([]byte, 4+len(meta)+len(request.Body))
	binary.BigEndian.PutUint32(encoded[:4], uint32(len(meta)))
	copy(encoded[4:], meta)
	copy(encoded[4+len(meta):], request.Body)
	return encoded, nil
}

func Decode(encoded []byte) (Request, error) {
	if len(encoded) < 4 {
		return Request{}, ErrInvalidEnvelope
	}
	metaLength := int(binary.BigEndian.Uint32(encoded[:4]))
	if metaLength <= 0 || metaLength > maxMetadataBytes || len(encoded) < 4+metaLength {
		return Request{}, ErrInvalidEnvelope
	}

	var meta metadata
	decoder := json.NewDecoder(bytes.NewReader(encoded[4 : 4+metaLength]))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&meta); err != nil {
		return Request{}, fmt.Errorf("%w: %v", ErrInvalidEnvelope, err)
	}
	if meta.Method == "" || meta.Path == "" || meta.ReceivedAt.IsZero() {
		return Request{}, ErrInvalidEnvelope
	}

	return Request{
		Method: meta.Method, Path: meta.Path, RawQuery: meta.RawQuery,
		Headers: meta.Headers, RemoteAddr: meta.RemoteAddr, ReceivedAt: meta.ReceivedAt,
		Body: append([]byte(nil), encoded[4+metaLength:]...),
	}, nil
}

package otlp

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/bussolabs/closeyourit-ingest-community/gateway/internal/cryptor"
	"github.com/bussolabs/closeyourit-ingest-community/gateway/internal/envelope"
	"github.com/bussolabs/closeyourit-ingest-community/gateway/internal/queue"
	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/exporter"
	"go.opentelemetry.io/collector/pdata/plog"
	"go.opentelemetry.io/collector/pdata/plog/plogotlp"
	"go.opentelemetry.io/collector/pdata/pmetric"
	"go.opentelemetry.io/collector/pdata/pmetric/pmetricotlp"
	"go.opentelemetry.io/collector/pdata/ptrace"
	"go.opentelemetry.io/collector/pdata/ptrace/ptraceotlp"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type Recorder interface {
	RecordOTLP(signal, outcome string, count int)
	RecordOTLPRequest(signal, outcome string)
}
type nopRecorder struct{}

func (nopRecorder) RecordOTLP(string, string, int)   {}
func (nopRecorder) RecordOTLPRequest(string, string) {}

type PartialError struct{ Rejected int64 }

func (e *PartialError) Error() string {
	return "Records rejected by attribute budgets, invalid or unsupported attribute values, or unsupported metric type"
}

// DurableExporter is a synchronous Collector exporter. Returning nil means a
// JetStream publish acknowledgement has been received, never merely buffered.
type DurableExporter struct {
	Publisher queue.Publisher
	Cryptor   *cryptor.Cryptor
	Recorder  Recorder
}

func (e *DurableExporter) Start(context.Context, component.Host) error { return nil }
func (e *DurableExporter) Shutdown(context.Context) error              { return nil }
func (e *DurableExporter) Capabilities() consumer.Capabilities {
	return consumer.Capabilities{MutatesData: false}
}
func (e *DurableExporter) ConsumeTraces(ctx context.Context, data ptrace.Traces) error {
	b, err := ptraceotlp.NewExportRequestFromTraces(data).MarshalJSON()
	return e.admit(ctx, "traces", b, err)
}
func (e *DurableExporter) ConsumeMetrics(ctx context.Context, data pmetric.Metrics) error {
	b, err := pmetricotlp.NewExportRequestFromMetrics(data).MarshalJSON()
	return e.admit(ctx, "metrics", b, err)
}
func (e *DurableExporter) ConsumeLogs(ctx context.Context, data plog.Logs) error {
	b, err := plogotlp.NewExportRequestFromLogs(data).MarshalJSON()
	return e.admit(ctx, "logs", b, err)
}

func NewExporterFactory(e *DurableExporter) exporter.Factory {
	return exporter.NewFactory(component.MustNewType("cyidurability"), func() component.Config { return &struct{}{} },
		exporter.WithTraces(func(context.Context, exporter.Settings, component.Config) (exporter.Traces, error) { return e, nil }, component.StabilityLevelAlpha),
		exporter.WithMetrics(func(context.Context, exporter.Settings, component.Config) (exporter.Metrics, error) { return e, nil }, component.StabilityLevelAlpha),
		exporter.WithLogs(func(context.Context, exporter.Settings, component.Config) (exporter.Logs, error) { return e, nil }, component.StabilityLevelAlpha))
}

func (e *DurableExporter) admit(ctx context.Context, signal string, encoded []byte, encodeErr error) error {
	principal, err := principalFrom(ctx)
	if err != nil {
		return status.Error(codes.Unauthenticated, "Authenticated project context is required")
	}
	if encodeErr != nil {
		return status.Error(codes.InvalidArgument, "Invalid OTLP request")
	}
	var body map[string]any
	if json.Unmarshal(encoded, &body) != nil {
		return status.Error(codes.InvalidArgument, "Invalid OTLP request")
	}
	recorder := e.Recorder
	if recorder == nil {
		recorder = nopRecorder{}
	}
	count := countSignal(signal, body)
	if count > MaxItems {
		recorder.RecordOTLP(signal, "item_limit", count)
		return status.Error(codes.InvalidArgument, "Export exceeds the 1000 item limit")
	}
	if count == 0 {
		return nil
	}
	rejected := filterSignal(signal, body, strings.TrimPrefix(principal.Credential, "Bearer "))
	scrubCredential(body, strings.TrimPrefix(principal.Credential, "Bearer "))
	accepted := count - rejected
	if accepted > 0 {
		encoded, err = json.Marshal(body)
		if err != nil || len(encoded) > MaxBodyBytes {
			return status.Error(codes.InvalidArgument, "Normalized export exceeds the body limit")
		}
		id := make([]byte, 16)
		if _, err = rand.Read(id); err != nil {
			return status.Error(codes.Unavailable, "Durable admission is unavailable")
		}
		request := envelope.Request{Method: "POST", Path: "/api/v1/projects/" + principal.ProjectID + "/otlp/" + signal,
			Headers: map[string]string{"Authorization": principal.Credential, "Content-Type": "application/json", "X-CloseYourIt-Organization-Id": principal.OrganizationID}, ReceivedAt: time.Now().UTC(), Body: encoded}
		plain, err := envelope.Encode(request)
		if err != nil {
			return status.Error(codes.Unavailable, "Durable admission is unavailable")
		}
		kind := "otlp_" + signal
		ciphertext, err := e.Cryptor.Encrypt(plain, []byte(kind))
		if err == nil {
			publishCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
			defer cancel()
			err = e.Publisher.Publish(publishCtx, queue.Message{ID: hex.EncodeToString(id), Kind: kind, Ciphertext: ciphertext})
		}
		if err != nil {
			recorder.RecordOTLP(signal, "queue_unavailable", count)
			return status.Error(codes.Unavailable, "Durable admission is unavailable")
		}
		recorder.RecordOTLP(signal, "accepted", accepted)
	}
	if rejected > 0 {
		recorder.RecordOTLP(signal, "rejected", rejected)
		return &PartialError{Rejected: int64(rejected)}
	}
	return nil
}

func partialCount(err error) (int64, string) {
	var p *PartialError
	if errors.As(err, &p) {
		return p.Rejected, p.Error()
	}
	return 0, ""
}

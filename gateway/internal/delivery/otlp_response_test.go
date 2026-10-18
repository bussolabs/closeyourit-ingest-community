package delivery

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"go.opentelemetry.io/collector/pdata/plog/plogotlp"
)

type rejectionRecorder struct {
	fakeRecorder
	rejected int64
}

func (r *rejectionRecorder) RecordOTLPDeliveryRejected(_ string, count int64) { r.rejected += count }

func TestOTLPPartialDeliveryRecordsRejectedItemsWithoutRetryingBatch(t *testing.T) {
	for _, signal := range []struct{ kind, field string }{{"otlp_traces", "rejectedSpans"}, {"otlp_metrics", "rejectedDataPoints"}, {"otlp_logs", "rejectedLogRecords"}} {
		t.Run(signal.kind, func(t *testing.T) {
			body := fmt.Sprintf(`{"partialSuccess":{%q:"2","errorMessage":"sensitive rejected payload"}}`, signal.field)
			client := &fakeHTTPClient{response: &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(strings.NewReader(body))}}
			dlq := &fakeDeadLetters{}
			worker, c := testWorker(t, client, dlq)
			recorder := &rejectionRecorder{}
			worker.SetRecorder(recorder)
			var logs bytes.Buffer
			worker.logger = slog.New(slog.NewJSONHandler(&logs, nil))
			message := encryptedDelivery(t, c, signal.kind, 1)
			acked := 0
			message.Ack = func(context.Context) error { acked++; return nil }
			message.Retry = func(time.Duration) error { t.Fatal("Partial success must never retry accepted items"); return nil }
			worker.process(context.Background(), message)
			if acked != 1 || dlq.calls != 0 || recorder.rejected != 2 || strings.Join(recorder.deliveries, ",") != signal.kind+":partial_success" || strings.Join(recorder.failures, ",") != "otlp_partial_rejection" {
				t.Fatalf("ack=%d dlq=%d rejected=%d outcomes=%v failures=%v", acked, dlq.calls, recorder.rejected, recorder.deliveries, recorder.failures)
			}
			if strings.Contains(logs.String(), "sensitive rejected payload") {
				t.Fatal("Upstream payload leaked into diagnostics")
			}
		})
	}
}

func TestOTLPInvalidSuccessResponsesAreQuarantinedWithoutRetry(t *testing.T) {
	for _, test := range []struct{ name, body, media, reason string }{
		{"malformed", "{", "application/json", "otlp_response_malformed"},
		{"trailing-data", "{}{}", "application/json", "otlp_response_malformed"},
		{"oversized", strings.Repeat(" ", maxOTLPResponseBytes) + "{}", "application/json", "otlp_response_too_large"},
		{"wrong-type", "<html>login</html>", "text/html", "otlp_response_content_type"},
		{"negative-count", `{"partialSuccess":{"rejectedSpans":"-1"}}`, "application/json", "otlp_response_malformed"},
		{"unbounded-count", `{"partialSuccess":{"rejectedSpans":"1001"}}`, "application/json", "otlp_response_malformed"},
	} {
		t.Run(test.name, func(t *testing.T) {
			client := &fakeHTTPClient{response: &http.Response{StatusCode: 200, Header: http.Header{"Content-Type": []string{test.media}}, Body: io.NopCloser(strings.NewReader(test.body))}}
			dlq := &fakeDeadLetters{}
			worker, c := testWorker(t, client, dlq)
			message := encryptedDelivery(t, c, "otlp_traces", 1)
			acked := 0
			message.Ack = func(context.Context) error { acked++; return nil }
			message.Retry = func(time.Duration) error {
				t.Fatal("Ambiguous success must be quarantined, not automatically replayed")
				return nil
			}
			worker.process(context.Background(), message)
			if dlq.calls != 1 || dlq.reason != test.reason || acked != 1 {
				t.Fatalf("dlq=%d reason=%s ack=%d", dlq.calls, dlq.reason, acked)
			}
		})
	}
}

func TestOTLPProtobufResponseAndWarnings(t *testing.T) {
	response := plogotlp.NewExportResponse()
	response.PartialSuccess().SetRejectedLogRecords(3)
	body, _ := response.MarshalProto()
	count, warning, err := inspectOTLPResponse("otlp_logs", &http.Response{Header: http.Header{"Content-Type": []string{"application/x-protobuf"}}, Body: io.NopCloser(bytes.NewReader(body))})
	if err != nil || count != 3 || warning {
		t.Fatalf("count=%d warning=%v err=%v", count, warning, err)
	}
	response = plogotlp.NewExportResponse()
	response.PartialSuccess().SetErrorMessage("warning only")
	body, _ = response.MarshalJSON()
	count, warning, err = inspectOTLPResponse("otlp_logs", &http.Response{Header: http.Header{"Content-Type": []string{"application/json"}}, Body: io.NopCloser(bytes.NewReader(body))})
	if err != nil || count != 0 || !warning {
		t.Fatalf("count=%d warning=%v err=%v", count, warning, err)
	}
}

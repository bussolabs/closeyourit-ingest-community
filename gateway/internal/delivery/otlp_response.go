package delivery

import (
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"

	"go.opentelemetry.io/collector/pdata/plog/plogotlp"
	"go.opentelemetry.io/collector/pdata/pmetric/pmetricotlp"
	"go.opentelemetry.io/collector/pdata/ptrace/ptraceotlp"
)

const maxOTLPResponseBytes = 1024 * 1024

type otlpResponse interface {
	UnmarshalJSON([]byte) error
	UnmarshalProto([]byte) error
}

// Diagnostics deliberately discard the upstream error message, which can contain
// rejected customer data. Only bounded reason names and counts leave this boundary.
func inspectOTLPResponse(kind string, response *http.Response) (int64, bool, error) {
	body, err := io.ReadAll(io.LimitReader(response.Body, maxOTLPResponseBytes+1))
	if err != nil {
		return 0, false, errors.New("otlp_response_read_failed")
	}
	if len(body) > maxOTLPResponseBytes {
		return 0, false, errors.New("otlp_response_too_large")
	}
	media, _, _ := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if media != "application/json" && media != "application/x-protobuf" {
		return 0, false, errors.New("otlp_response_content_type")
	}
	if media == "application/json" && !json.Valid(body) {
		return 0, false, errors.New("otlp_response_malformed")
	}
	var message otlpResponse
	var count func() int64
	var warning func() bool
	switch kind {
	case "otlp_traces":
		result := ptraceotlp.NewExportResponse()
		message = result
		count = func() int64 { return result.PartialSuccess().RejectedSpans() }
		warning = func() bool { return result.PartialSuccess().ErrorMessage() != "" }
	case "otlp_metrics":
		result := pmetricotlp.NewExportResponse()
		message = result
		count = func() int64 { return result.PartialSuccess().RejectedDataPoints() }
		warning = func() bool { return result.PartialSuccess().ErrorMessage() != "" }
	case "otlp_logs":
		result := plogotlp.NewExportResponse()
		message = result
		count = func() int64 { return result.PartialSuccess().RejectedLogRecords() }
		warning = func() bool { return result.PartialSuccess().ErrorMessage() != "" }
	default:
		return 0, false, errors.New("otlp_response_unknown_signal")
	}
	if media == "application/json" {
		err = message.UnmarshalJSON(body)
	} else {
		err = message.UnmarshalProto(body)
	}
	if err != nil || count() < 0 || count() > 1000 {
		return 0, false, errors.New("otlp_response_malformed")
	}
	return count(), warning(), nil
}

type otlpRejectionRecorder interface {
	RecordOTLPDeliveryRejected(kind string, count int64)
}

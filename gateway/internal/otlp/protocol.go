package otlp

import (
	"context"

	"go.opentelemetry.io/collector/pdata/plog/plogotlp"
	"go.opentelemetry.io/collector/pdata/pmetric/pmetricotlp"
	"go.opentelemetry.io/collector/pdata/ptrace/ptraceotlp"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type exportMessage interface {
	UnmarshalJSON([]byte) error
	UnmarshalProto([]byte) error
}
type exportResponse interface {
	MarshalJSON() ([]byte, error)
	MarshalProto() ([]byte, error)
}

func decode(request exportMessage, body []byte, jsonFormat bool) error {
	var err error
	if jsonFormat {
		err = request.UnmarshalJSON(body)
	} else {
		err = request.UnmarshalProto(body)
	}
	if err != nil {
		return status.Error(codes.InvalidArgument, "Invalid OTLP request")
	}
	return nil
}
func encode(response exportResponse, jsonFormat bool) ([]byte, error) {
	if jsonFormat {
		return response.MarshalJSON()
	}
	return response.MarshalProto()
}

func (r *Receiver) export(ctx context.Context, signal string, body []byte, jsonFormat bool) ([]byte, error) {
	switch signal {
	case "traces":
		request := ptraceotlp.NewExportRequest()
		if err := decode(request, body, jsonFormat); err != nil {
			return nil, err
		}
		response, err := (traceServer{receiver: r}).Export(ctx, request)
		if err != nil {
			return nil, err
		}
		return encode(response, jsonFormat)
	case "metrics":
		request := pmetricotlp.NewExportRequest()
		if err := decode(request, body, jsonFormat); err != nil {
			return nil, err
		}
		response, err := (metricServer{receiver: r}).Export(ctx, request)
		if err != nil {
			return nil, err
		}
		return encode(response, jsonFormat)
	default:
		request := plogotlp.NewExportRequest()
		if err := decode(request, body, jsonFormat); err != nil {
			return nil, err
		}
		response, err := (logServer{receiver: r}).Export(ctx, request)
		if err != nil {
			return nil, err
		}
		return encode(response, jsonFormat)
	}
}

type traceServer struct {
	ptraceotlp.UnimplementedGRPCServer
	receiver *Receiver
}

func (s traceServer) Export(ctx context.Context, request ptraceotlp.ExportRequest) (ptraceotlp.ExportResponse, error) {
	response := ptraceotlp.NewExportResponse()
	err := s.receiver.Traces.ConsumeTraces(ctx, request.Traces())
	if count, message := partialCount(err); count > 0 {
		response.PartialSuccess().SetRejectedSpans(count)
		response.PartialSuccess().SetErrorMessage(message)
		return response, nil
	}
	return response, err
}

type metricServer struct {
	pmetricotlp.UnimplementedGRPCServer
	receiver *Receiver
}

func (s metricServer) Export(ctx context.Context, request pmetricotlp.ExportRequest) (pmetricotlp.ExportResponse, error) {
	response := pmetricotlp.NewExportResponse()
	err := s.receiver.Metrics.ConsumeMetrics(ctx, request.Metrics())
	if count, message := partialCount(err); count > 0 {
		response.PartialSuccess().SetRejectedDataPoints(count)
		response.PartialSuccess().SetErrorMessage(message)
		return response, nil
	}
	return response, err
}

type logServer struct {
	plogotlp.UnimplementedGRPCServer
	receiver *Receiver
}

func (s logServer) Export(ctx context.Context, request plogotlp.ExportRequest) (plogotlp.ExportResponse, error) {
	response := plogotlp.NewExportResponse()
	err := s.receiver.Logs.ConsumeLogs(ctx, request.Logs())
	if count, message := partialCount(err); count > 0 {
		response.PartialSuccess().SetRejectedLogRecords(count)
		response.PartialSuccess().SetErrorMessage(message)
		return response, nil
	}
	return response, err
}

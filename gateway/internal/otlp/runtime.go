package otlp

import (
	"context"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/exporter"
	"go.opentelemetry.io/collector/receiver"
)

// NewPipeline wires real Collector factories without an asynchronous batch
// processor or exporterhelper queue, so tenant context and admission errors
// stay attached to the originating Export request.
func NewPipeline(ctx context.Context, config Config, auth Authorizer, durable *DurableExporter) (*Receiver, error) {
	exporterFactory := NewExporterFactory(durable)
	exportConfig := exporterFactory.CreateDefaultConfig()
	traces, err := exporterFactory.CreateTraces(ctx, exporter.Settings{ID: component.NewID(exporterFactory.Type())}, exportConfig)
	if err != nil {
		return nil, err
	}
	metrics, err := exporterFactory.CreateMetrics(ctx, exporter.Settings{ID: component.NewID(exporterFactory.Type())}, exportConfig)
	if err != nil {
		return nil, err
	}
	logs, err := exporterFactory.CreateLogs(ctx, exporter.Settings{ID: component.NewID(exporterFactory.Type())}, exportConfig)
	if err != nil {
		return nil, err
	}
	r := &Receiver{Authorizer: auth, Recorder: durable.Recorder}
	factory := NewReceiverFactory(r)
	if _, err = factory.CreateTraces(ctx, receiver.Settings{ID: component.NewID(factory.Type())}, &config, traces); err != nil {
		return nil, err
	}
	if _, err = factory.CreateMetrics(ctx, receiver.Settings{ID: component.NewID(factory.Type())}, &config, metrics); err != nil {
		return nil, err
	}
	if _, err = factory.CreateLogs(ctx, receiver.Settings{ID: component.NewID(factory.Type())}, &config, logs); err != nil {
		return nil, err
	}
	return r, nil
}

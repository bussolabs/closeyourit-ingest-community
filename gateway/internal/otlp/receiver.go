// Package otlp embeds a synchronous Collector receiver/exporter pipeline. The
// custom receiver preserves partial-success counts that otlpreceiver v0.162.0
// currently discards; parsing and gRPC services use official Collector pdata.
package otlp

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"go.opentelemetry.io/collector/component"
	"go.opentelemetry.io/collector/consumer"
	"go.opentelemetry.io/collector/pdata/plog/plogotlp"
	"go.opentelemetry.io/collector/pdata/pmetric/pmetricotlp"
	"go.opentelemetry.io/collector/pdata/ptrace/ptraceotlp"
	"go.opentelemetry.io/collector/receiver"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	_ "google.golang.org/grpc/encoding/gzip"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/stats"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
)

type Config struct{ HTTPAddress, GRPCAddress string }

func (c *Config) Validate() error {
	if c.HTTPAddress == "" || c.GRPCAddress == "" {
		return errors.New("Both OTLP listener addresses are required")
	}
	return nil
}

type Receiver struct {
	Config                     Config
	Authorizer                 Authorizer
	Traces                     consumer.Traces
	Metrics                    consumer.Metrics
	Logs                       consumer.Logs
	Recorder                   Recorder
	HTTPListener, GRPCListener net.Listener
	Errors                     chan error
	http                       *http.Server
	grpc                       *grpc.Server
	mu                         sync.Mutex
	projects                   map[string]quota
}
type quota struct {
	count int
	until time.Time
}

func NewReceiverFactory(r *Receiver) receiver.Factory {
	return receiver.NewFactory(component.MustNewType("cyiotlp"), func() component.Config { return &Config{HTTPAddress: "127.0.0.1:4318", GRPCAddress: "127.0.0.1:4317"} },
		receiver.WithTraces(func(_ context.Context, _ receiver.Settings, c component.Config, next consumer.Traces) (receiver.Traces, error) {
			r.Config = *c.(*Config)
			r.Traces = next
			return r, nil
		}, component.StabilityLevelAlpha),
		receiver.WithMetrics(func(_ context.Context, _ receiver.Settings, c component.Config, next consumer.Metrics) (receiver.Metrics, error) {
			r.Config = *c.(*Config)
			r.Metrics = next
			return r, nil
		}, component.StabilityLevelAlpha),
		receiver.WithLogs(func(_ context.Context, _ receiver.Settings, c component.Config, next consumer.Logs) (receiver.Logs, error) {
			r.Config = *c.(*Config)
			r.Logs = next
			return r, nil
		}, component.StabilityLevelAlpha))
}

func (r *Receiver) Start(ctx context.Context, _ component.Host) error {
	if err := r.Config.Validate(); err != nil {
		return err
	}
	if r.Authorizer == nil || r.Traces == nil || r.Metrics == nil || r.Logs == nil {
		return errors.New("Authorization and all signal consumers are required")
	}
	var err error
	r.HTTPListener, err = net.Listen("tcp", r.Config.HTTPAddress)
	if err != nil {
		return err
	}
	r.GRPCListener, err = net.Listen("tcp", r.Config.GRPCAddress)
	if err != nil {
		r.HTTPListener.Close()
		return err
	}
	r.Errors = make(chan error, 2)
	r.http = &http.Server{Handler: r, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 20 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 * 1024}
	r.grpc = grpc.NewServer(grpc.MaxRecvMsgSize(MaxBodyBytes), grpc.MaxSendMsgSize(MaxWireBytes), grpc.MaxConcurrentStreams(32), grpc.StatsHandler(wireBudget{}), grpc.UnaryInterceptor(r.authenticateRPC))
	ptraceotlp.RegisterGRPCServer(r.grpc, &traceServer{receiver: r})
	pmetricotlp.RegisterGRPCServer(r.grpc, &metricServer{receiver: r})
	plogotlp.RegisterGRPCServer(r.grpc, &logServer{receiver: r})
	go func() {
		err := r.http.Serve(r.HTTPListener)
		if !errors.Is(err, http.ErrServerClosed) {
			r.Errors <- err
		}
	}()
	go func() {
		err := r.grpc.Serve(r.GRPCListener)
		if !errors.Is(err, grpc.ErrServerStopped) {
			r.Errors <- err
		}
	}()
	return nil
}

func (r *Receiver) Shutdown(ctx context.Context) error {
	if r.grpc != nil {
		done := make(chan struct{})
		go func() { r.grpc.GracefulStop(); close(done) }()
		select {
		case <-done:
		case <-ctx.Done():
			r.grpc.Stop()
		}
	}
	if r.http != nil {
		return r.http.Shutdown(ctx)
	}
	return nil
}

func (r *Receiver) authorize(ctx context.Context, credential string) (context.Context, error) {
	p, err := r.Authorizer.Authorize(ctx, credential)
	if err != nil {
		return ctx, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.projects == nil {
		r.projects = map[string]quota{}
	}
	now := time.Now()
	q := r.projects[p.ProjectID]
	if q.until.Before(now) {
		q = quota{until: now.Add(time.Minute)}
	}
	if q.count >= 600 {
		s, _ := status.New(codes.ResourceExhausted, "Project ingest request quota exceeded").WithDetails(&errdetails.RetryInfo{RetryDelay: durationpb.New(time.Minute)})
		return ctx, s.Err()
	}
	if len(r.projects) >= 10000 {
		for id, q := range r.projects {
			if q.until.Before(now) {
				delete(r.projects, id)
			}
		}
		if _, exists := r.projects[p.ProjectID]; !exists && len(r.projects) >= 10000 {
			return ctx, status.Error(codes.Unavailable, "Admission capacity is exhausted")
		}
	}
	q.count++
	r.projects[p.ProjectID] = q
	return withPrincipal(ctx, p), nil
}

func (r *Receiver) ServeHTTP(w http.ResponseWriter, request *http.Request) {
	signal := signalForPath(request.URL.Path)
	if signal == "" {
		http.NotFound(w, request)
		return
	}
	observed := &observedResponse{ResponseWriter: w, code: 200}
	w = observed
	if r.Recorder != nil {
		defer func() { r.Recorder.RecordOTLPRequest(signal, "http_"+strconv.Itoa(observed.code)) }()
	}
	if request.Method != http.MethodPost {
		w.Header().Set("Allow", "POST")
		writeHTTPError(w, false, status.Error(codes.InvalidArgument, "Only POST is supported"), 405)
		return
	}
	media, _, _ := mime.ParseMediaType(request.Header.Get("Content-Type"))
	jsonFormat := media == "application/json"
	if !jsonFormat && media != "application/x-protobuf" {
		writeHTTPError(w, false, status.Error(codes.InvalidArgument, "Unsupported content type"), 415)
		return
	}
	ctx, err := r.authorize(request.Context(), request.Header.Get("Authorization"))
	if err != nil {
		writeHTTPError(w, jsonFormat, err, 0)
		return
	}
	wire, err := io.ReadAll(io.LimitReader(request.Body, MaxWireBytes+1))
	if err != nil {
		writeHTTPError(w, jsonFormat, status.Error(codes.InvalidArgument, "Invalid request body"), 400)
		return
	}
	if len(wire) > MaxWireBytes {
		writeHTTPError(w, jsonFormat, status.Error(codes.InvalidArgument, "Compressed request exceeds 1 MiB"), 413)
		return
	}
	body := wire
	switch request.Header.Get("Content-Encoding") {
	case "", "identity":
	case "gzip":
		reader, gzipErr := gzip.NewReader(bytes.NewReader(wire))
		if gzipErr != nil {
			writeHTTPError(w, jsonFormat, status.Error(codes.InvalidArgument, "Invalid gzip body"), 400)
			return
		}
		body, err = io.ReadAll(io.LimitReader(reader, MaxBodyBytes+1))
		reader.Close()
		if err != nil {
			writeHTTPError(w, jsonFormat, status.Error(codes.InvalidArgument, "Invalid gzip body"), 400)
			return
		}
	default:
		writeHTTPError(w, jsonFormat, status.Error(codes.InvalidArgument, "Unsupported content encoding"), 415)
		return
	}
	if len(body) > MaxBodyBytes {
		writeHTTPError(w, jsonFormat, status.Error(codes.InvalidArgument, "Decompressed request exceeds 5 MiB"), 413)
		return
	}
	if jsonFormat && !json.Valid(body) {
		writeHTTPError(w, jsonFormat, status.Error(codes.InvalidArgument, "Invalid OTLP JSON request"), 400)
		return
	}
	response, err := r.export(ctx, signal, body, jsonFormat)
	if err != nil {
		writeHTTPError(w, jsonFormat, err, 0)
		return
	}
	if jsonFormat {
		w.Header().Set("Content-Type", "application/json")
	} else {
		w.Header().Set("Content-Type", "application/x-protobuf")
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(response)
}

func writeHTTPError(w http.ResponseWriter, jsonFormat bool, err error, code int) {
	s := status.Convert(err)
	if code == 0 {
		switch s.Code() {
		case codes.Unauthenticated:
			code = 401
		case codes.PermissionDenied:
			code = 403
		case codes.InvalidArgument:
			code = 400
		case codes.ResourceExhausted:
			code = 429
		default:
			code = 503
		}
	}
	if code == 429 || code == 503 {
		w.Header().Set("Retry-After", "1")
	}
	var body []byte
	if jsonFormat {
		w.Header().Set("Content-Type", "application/json")
		body, _ = protojson.Marshal(s.Proto())
	} else {
		w.Header().Set("Content-Type", "application/x-protobuf")
		body, _ = proto.Marshal(s.Proto())
	}
	w.WriteHeader(code)
	_, _ = w.Write(body)
}

type rpcBudgetKey struct{}
type wireBudget struct{}

func (wireBudget) TagRPC(ctx context.Context, _ *stats.RPCTagInfo) context.Context {
	return context.WithValue(ctx, rpcBudgetKey{}, &atomic.Int64{})
}
func (wireBudget) HandleRPC(ctx context.Context, event stats.RPCStats) {
	if payload, ok := event.(*stats.InPayload); ok {
		ctx.Value(rpcBudgetKey{}).(*atomic.Int64).Store(int64(payload.WireLength))
	}
}
func (wireBudget) TagConn(ctx context.Context, _ *stats.ConnTagInfo) context.Context { return ctx }
func (wireBudget) HandleConn(context.Context, stats.ConnStats)                       {}
func (r *Receiver) authenticateRPC(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (response any, exportErr error) {
	signal := "unknown"
	for _, candidate := range []string{"Trace", "Metrics", "Logs"} {
		if strings.Contains(info.FullMethod, candidate+"Service") {
			signal = map[string]string{"Trace": "traces", "Metrics": "metrics", "Logs": "logs"}[candidate]
		}
	}
	if r.Recorder != nil {
		defer func() { r.Recorder.RecordOTLPRequest(signal, "grpc_"+status.Code(exportErr).String()) }()
	}
	if budget, ok := ctx.Value(rpcBudgetKey{}).(*atomic.Int64); ok && budget.Load() > MaxWireBytes+5 {
		return nil, status.Error(codes.ResourceExhausted, "Compressed request exceeds 1 MiB")
	}
	md, _ := metadata.FromIncomingContext(ctx)
	values := md.Get("authorization")
	if len(values) != 1 {
		return nil, status.Error(codes.Unauthenticated, "A project bearer credential is required")
	}
	ctx, err := r.authorize(ctx, values[0])
	if err != nil {
		return nil, err
	}
	return handler(ctx, req)
}

type observedResponse struct {
	http.ResponseWriter
	code int
}

func (w *observedResponse) WriteHeader(code int) { w.code = code; w.ResponseWriter.WriteHeader(code) }

package otlp

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/bussolabs/closeyourit-ingest-community/gateway/internal/cryptor"
	"github.com/bussolabs/closeyourit-ingest-community/gateway/internal/envelope"
	"github.com/bussolabs/closeyourit-ingest-community/gateway/internal/natsstore"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"go.opentelemetry.io/collector/pdata/plog/plogotlp"
	"go.opentelemetry.io/collector/pdata/ptrace/ptraceotlp"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const testProjectA = "a0000000-0000-4000-8000-000000000001"
const testProjectB = "b0000000-0000-4000-8000-000000000002"
const testOrganization = "c0000000-0000-4000-8000-000000000003"

type harness struct {
	receiver *Receiver
	store    *natsstore.Store
	cipher   *cryptor.Cryptor
	broker   *server.Server
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	auth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/otlp/authorizations" || r.Method != "POST" {
			t.Errorf("Unexpected authorization route: %s", r.URL.Path)
			w.WriteHeader(404)
			return
		}
		project := ""
		switch r.Header.Get("Authorization") {
		case "Bearer test-project-a":
			project = testProjectA
		case "Bearer test-project-b":
			project = testProjectB
		default:
			w.WriteHeader(401)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]string{"project_id": project, "organization_id": testOrganization}})
	}))
	t.Cleanup(auth.Close)
	u, _ := url.Parse(auth.URL)
	return newHarnessWithAuthorizer(t, RemoteAuthorizer{Upstream: u, Client: auth.Client()})
}

func newHarnessWithAuthorizer(t *testing.T, authorizer Authorizer) *harness {
	t.Helper()
	broker, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1, JetStream: true, JetStreamMaxStore: 32 * 1024 * 1024 * 1024, StoreDir: t.TempDir(), MaxPayload: 6 * 1024 * 1024, NoLog: true, NoSigs: true})
	if err != nil {
		t.Fatal(err)
	}
	broker.Start()
	if !broker.ReadyForConnections(5 * time.Second) {
		t.Fatal("JetStream did not start")
	}
	t.Cleanup(broker.Shutdown)
	nc, err := nats.Connect(broker.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(nc.Close)
	js, err := jetstream.New(nc)
	if err != nil {
		t.Fatal(err)
	}
	store, err := natsstore.Setup(context.Background(), js)
	if err != nil {
		t.Fatal(err)
	}
	key := make([]byte, 32)
	if _, err = rand.Read(key); err != nil {
		t.Fatal(err)
	}
	cipher, err := cryptor.New(base64.StdEncoding.EncodeToString(key))
	if err != nil {
		t.Fatal(err)
	}
	receiver, err := NewPipeline(context.Background(), Config{HTTPAddress: "127.0.0.1:0", GRPCAddress: "127.0.0.1:0"}, authorizer, &DurableExporter{Publisher: store, Cryptor: cipher})
	if err != nil {
		t.Fatal(err)
	}
	if err = receiver.Start(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = receiver.Shutdown(ctx)
	})
	return &harness{receiver: receiver, store: store, cipher: cipher, broker: broker}
}

func (h *harness) post(t *testing.T, signal string, body []byte, contentType, encoding, credential string) (int, []byte) {
	t.Helper()
	req, _ := http.NewRequest("POST", "http://"+h.receiver.HTTPListener.Addr().String()+"/v1/"+signal, bytes.NewReader(body))
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Content-Encoding", encoding)
	req.Header.Set("Authorization", credential)
	req.Header.Set("X-CloseYourIt-Organization-Id", "attacker-organization")
	req.Header.Set("X-CloseYourIt-Project-Id", "project-b")
	response, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	data, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return response.StatusCode, data
}

func (h *harness) next(t *testing.T) envelope.Request {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	message, err := h.store.Next(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(message.Ciphertext, []byte("Bearer")) {
		t.Fatal("Credential leaked outside encryption")
	}
	plain, err := h.cipher.Decrypt(message.Ciphertext, []byte(message.Kind))
	if err != nil {
		t.Fatal(err)
	}
	request, err := envelope.Decode(plain)
	if err != nil {
		t.Fatal(err)
	}
	if err = message.Ack(ctx); err != nil {
		t.Fatal(err)
	}
	return request
}

func TestOfficialSDKExportsAreDurablyAdmittedOverHTTPAndGRPC(t *testing.T) {
	h := newHarness(t)
	for _, protocol := range []string{"http", "grpc"} {
		t.Run(protocol, func(t *testing.T) {
			ctx := context.Background()
			var exporter sdktrace.SpanExporter
			var err error
			if protocol == "http" {
				exporter, err = otlptracehttp.New(ctx, otlptracehttp.WithEndpoint(h.receiver.HTTPListener.Addr().String()), otlptracehttp.WithInsecure(), otlptracehttp.WithHeaders(map[string]string{"Authorization": "Bearer test-project-a"}), otlptracehttp.WithCompression(otlptracehttp.GzipCompression))
			} else {
				exporter, err = otlptracegrpc.New(ctx, otlptracegrpc.WithEndpoint(h.receiver.GRPCListener.Addr().String()), otlptracegrpc.WithInsecure(), otlptracegrpc.WithHeaders(map[string]string{"Authorization": "Bearer test-project-a"}), otlptracegrpc.WithCompressor("gzip"))
			}
			if err != nil {
				t.Fatal(err)
			}
			provider := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))
			_, span := provider.Tracer("integration-test").Start(ctx, "real-sdk-export")
			span.SetAttributes(attribute.String("secret.token", "must-not-survive"), attribute.String("tenant.id", "attacker-project"))
			span.End()
			if err = provider.Shutdown(ctx); err != nil {
				t.Fatal(err)
			}
			stored := h.next(t)
			if stored.Path != "/api/v1/projects/"+testProjectA+"/otlp/traces" || stored.Headers["X-CloseYourIt-Organization-Id"] != testOrganization {
				t.Fatalf("Incorrect authenticated route: %+v", stored)
			}
			if bytes.Contains(stored.Body, []byte("must-not-survive")) {
				t.Fatal("Sensitive attribute reached durable storage")
			}
			request := ptraceotlp.NewExportRequest()
			if err = request.UnmarshalJSON(stored.Body); err != nil {
				t.Fatal(err)
			}
			if request.Traces().SpanCount() != 1 {
				t.Fatal("Expected exactly one SDK span")
			}
		})
	}
}

func TestPartialSuccessRejectsOnlyInvalidRecords(t *testing.T) {
	h := newHarness(t)
	request := plogotlp.NewExportRequest()
	scope := request.Logs().ResourceLogs().AppendEmpty().ScopeLogs().AppendEmpty()
	scope.LogRecords().AppendEmpty().Body().SetStr("accepted")
	bad := scope.LogRecords().AppendEmpty()
	bad.Body().SetStr("rejected")
	bad.Attributes().PutStr(strings.Repeat("k", 257), "value")
	body, _ := request.MarshalJSON()
	code, response := h.post(t, "logs", body, "application/json", "", "Bearer test-project-a")
	if code != 200 {
		t.Fatalf("status=%d body=%s", code, response)
	}
	result := plogotlp.NewExportResponse()
	if err := result.UnmarshalJSON(response); err != nil {
		t.Fatal(err)
	}
	if result.PartialSuccess().RejectedLogRecords() != 1 {
		t.Fatal("Expected one rejected log record")
	}
	stored := h.next(t)
	decoded := plogotlp.NewExportRequest()
	if err := decoded.UnmarshalJSON(stored.Body); err != nil {
		t.Fatal(err)
	}
	if decoded.Logs().LogRecordCount() != 1 || decoded.Logs().ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0).Body().Str() != "accepted" {
		t.Fatal("Partial admission changed surviving records")
	}
}

func TestMalformedUnauthorizedAndOversizedExportsNeverEnterQueue(t *testing.T) {
	h := newHarness(t)
	var compressed bytes.Buffer
	zip := gzip.NewWriter(&compressed)
	_, _ = zip.Write(bytes.Repeat([]byte("x"), MaxBodyBytes+1))
	_ = zip.Close()
	tests := []struct {
		name                 string
		body                 []byte
		encoding, credential string
		code                 int
	}{
		{"unauthorized", []byte("{}"), "", "public-dsn", 401},
		{"malformed", []byte("{"), "", "Bearer test-project-a", 400},
		{"trailing-data", []byte("{}{}"), "", "Bearer test-project-a", 400},
		{"wire-limit", bytes.Repeat([]byte("x"), MaxWireBytes+1), "", "Bearer test-project-a", 413},
		{"decompression-limit", compressed.Bytes(), "gzip", "Bearer test-project-a", 413},
		{"invalid-gzip", []byte("wrong"), "gzip", "Bearer test-project-a", 400},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			code, _ := h.post(t, "traces", test.body, "application/json", test.encoding, test.credential)
			if code != test.code {
				t.Fatalf("status=%d expected=%d", code, test.code)
			}
		})
	}
	stats, err := h.store.Stats(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, stream := range stats.Streams {
		if stream.Messages != 0 {
			t.Fatal("Rejected export entered durable storage")
		}
	}
}

func TestEmptyAndItemLimitExports(t *testing.T) {
	h := newHarness(t)
	code, _ := h.post(t, "traces", []byte(`{"resourceSpans":[],"futureField":true}`), "application/json", "", "Bearer test-project-a")
	if code != 200 {
		t.Fatalf("Empty export status=%d", code)
	}
	req := plogotlp.NewExportRequest()
	records := req.Logs().ResourceLogs().AppendEmpty().ScopeLogs().AppendEmpty().LogRecords()
	for range MaxItems + 1 {
		records.AppendEmpty().Body().SetStr("line")
	}
	body, _ := req.MarshalProto()
	code, _ = h.post(t, "logs", body, "application/x-protobuf", "", "Bearer test-project-a")
	if code != 400 {
		t.Fatalf("Item-limit status=%d", code)
	}
	stats, err := h.store.Stats(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, stream := range stats.Streams {
		if stream.Messages != 0 {
			t.Fatal("Empty or oversized export was queued")
		}
	}
}

func TestGRPCAuthenticationAndPartialSuccess(t *testing.T) {
	h := newHarness(t)
	conn, err := grpc.NewClient(h.receiver.GRPCListener.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	client := plogotlp.NewGRPCClient(conn)
	request := plogotlp.NewExportRequest()
	request.Logs().ResourceLogs().AppendEmpty().Resource().Attributes().PutStr(strings.Repeat("k", 257), "v")
	request.Logs().ResourceLogs().At(0).ScopeLogs().AppendEmpty().LogRecords().AppendEmpty().Body().SetStr("invalid")
	if _, err = client.Export(context.Background(), request); status.Code(err) != codes.Unauthenticated {
		t.Fatalf("Expected unauthenticated, got %v", err)
	}
	ctx := metadata.AppendToOutgoingContext(context.Background(), "authorization", "Bearer test-project-b")
	response, err := client.Export(ctx, request)
	if err != nil {
		t.Fatal(err)
	}
	if response.PartialSuccess().RejectedLogRecords() != 1 {
		t.Fatal("Missing gRPC partial rejection count")
	}
}

func TestQueueUnavailableCannotReturnSuccess(t *testing.T) {
	h := newHarness(t)
	h.broker.Shutdown()
	h.broker.WaitForShutdown()
	request := plogotlp.NewExportRequest()
	request.Logs().ResourceLogs().AppendEmpty().ScopeLogs().AppendEmpty().LogRecords().AppendEmpty().Body().SetStr("line")
	body, _ := request.MarshalJSON()
	code, response := h.post(t, "logs", body, "application/json", "", "Bearer test-project-a")
	if code != 503 {
		t.Fatalf("Unacknowledged publish returned %d: %s", code, response)
	}
}

func TestConcurrentProjectsRemainIsolated(t *testing.T) {
	h := newHarness(t)
	done := make(chan error, 20)
	for i := range 20 {
		go func(i int) {
			project := "a"
			if i%2 != 0 {
				project = "b"
			}
			body := fmt.Sprintf(`{"resourceLogs":[{"scopeLogs":[{"logRecords":[{"body":{"stringValue":"%s"}}]}]}]}`, project)
			req, _ := http.NewRequest("POST", "http://"+h.receiver.HTTPListener.Addr().String()+"/v1/logs", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer test-project-"+project)
			response, err := http.DefaultClient.Do(req)
			if err == nil {
				response.Body.Close()
				if response.StatusCode != 200 {
					err = fmt.Errorf("status=%d", response.StatusCode)
				}
			}
			done <- err
		}(i)
	}
	for range 20 {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
	for range 20 {
		stored := h.next(t)
		req := plogotlp.NewExportRequest()
		if err := req.UnmarshalJSON(stored.Body); err != nil {
			t.Fatal(err)
		}
		project := req.Logs().ResourceLogs().At(0).ScopeLogs().At(0).LogRecords().At(0).Body().Str()
		expected := testProjectA
		if project == "b" {
			expected = testProjectB
		}
		if stored.Path != "/api/v1/projects/"+expected+"/otlp/logs" {
			t.Fatal("Concurrent export crossed project boundary")
		}
	}
}

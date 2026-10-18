package otlp

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"go.opentelemetry.io/collector/pdata/ptrace/ptraceotlp"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
)

// This opt-in test consumes ephemeral Rails credentials only through an anonymous
// stdin pipe. It verifies authorization and durable admission, not Rails signal
// persistence. The external certification lifecycle owns database setup and cleanup.
func TestRailsAuthorizedOfficialSDKAdmission(t *testing.T) {
	if os.Getenv("CYI_OTLP_RAILS_TEST") != "1" {
		t.Skip("Requires an isolated certification Rails backend and private stdin configuration")
	}
	info, err := os.Stdin.Stat()
	if err != nil || info.Mode()&os.ModeNamedPipe == 0 {
		t.Fatal("Integration configuration requires an anonymous stdin pipe")
	}
	var config struct {
		Endpoint       string `json:"endpoint"`
		ProjectID      string `json:"project_id"`
		OtherProjectID string `json:"other_project_id"`
		IngestToken    string `json:"ingest_token"`
		ReadToken      string `json:"read_token"`
		PublicKey      string `json:"public_key"`
		BackendSHA     string `json:"backend_sha"`
	}
	body, err := io.ReadAll(io.LimitReader(os.Stdin, 16*1024+1))
	if err != nil || len(body) > 16*1024 || json.Unmarshal(body, &config) != nil {
		t.Fatal("Invalid private integration configuration")
	}
	endpoint, err := url.Parse(config.Endpoint)
	if err != nil || endpoint.Scheme != "http" || endpoint.Hostname() != "127.0.0.1" || endpoint.User != nil || endpoint.RawQuery != "" || endpoint.Fragment != "" || (endpoint.Path != "" && endpoint.Path != "/") {
		t.Fatal("Integration backend must be a plain loopback HTTP endpoint")
	}
	if !identifier.MatchString(config.ProjectID) || !identifier.MatchString(config.OtherProjectID) || config.IngestToken == "" || config.ReadToken == "" || config.PublicKey == "" || len(config.BackendSHA) != 40 {
		t.Fatal("Private integration configuration is incomplete")
	}
	client := &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Get(config.Endpoint + "/version")
	if err != nil {
		t.Fatal("Backend identity request failed")
	}
	versionBody, readErr := io.ReadAll(io.LimitReader(response.Body, 16*1024+1))
	response.Body.Close()
	var identity struct {
		SHA string `json:"sha"`
	}
	if readErr != nil || response.StatusCode != 200 || json.Unmarshal(versionBody, &identity) != nil || identity.SHA != config.BackendSHA {
		t.Fatal("Observed backend identity does not match the expected checkout")
	}
	authorizer := RemoteAuthorizer{Upstream: endpoint, Client: client}
	principal, err := authorizer.Authorize(context.Background(), "Bearer "+config.IngestToken)
	if err != nil || principal.ProjectID != config.ProjectID {
		t.Fatal("Real Rails authorization did not resolve the expected project")
	}
	h := newHarnessWithAuthorizer(t, authorizer)
	for _, protocol := range []string{"http", "grpc"} {
		t.Run(protocol, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			var exporter sdktrace.SpanExporter
			var err error
			headers := map[string]string{"Authorization": "Bearer " + config.IngestToken, "X-CloseYourIt-Project-Id": config.OtherProjectID, "X-CloseYourIt-Organization-Id": "spoofed-organization"}
			if protocol == "http" {
				exporter, err = otlptracehttp.New(ctx, otlptracehttp.WithEndpoint(h.receiver.HTTPListener.Addr().String()), otlptracehttp.WithInsecure(), otlptracehttp.WithHeaders(headers), otlptracehttp.WithCompression(otlptracehttp.GzipCompression))
			} else {
				exporter, err = otlptracegrpc.New(ctx, otlptracegrpc.WithEndpoint(h.receiver.GRPCListener.Addr().String()), otlptracegrpc.WithInsecure(), otlptracegrpc.WithHeaders(headers), otlptracegrpc.WithCompressor("gzip"))
			}
			if err != nil {
				t.Fatal("Official SDK exporter initialization failed")
			}
			provider := sdktrace.NewTracerProvider(sdktrace.WithSyncer(exporter))
			_, span := provider.Tracer("cyi-rails-admission-integration").Start(ctx, "rails-authorized-"+protocol)
			span.SetAttributes(attribute.String("project.id", config.OtherProjectID), attribute.String("debug.message", "request failed: "+config.IngestToken))
			span.End()
			if err = provider.Shutdown(ctx); err != nil {
				t.Fatal("Official SDK exporter shutdown failed")
			}
			stored := h.next(t)
			if stored.Path != "/api/v1/projects/"+config.ProjectID+"/otlp/traces" || stored.Headers["X-CloseYourIt-Organization-Id"] != principal.OrganizationID {
				t.Fatal("Caller-supplied routing escaped authenticated Rails identity")
			}
			if bytes.Contains(stored.Body, []byte(config.IngestToken)) {
				t.Fatal("Ephemeral credential survived telemetry scrubbing")
			}
			request := ptraceotlp.NewExportRequest()
			if err = request.UnmarshalJSON(stored.Body); err != nil || request.Traces().SpanCount() != 1 {
				t.Fatal("Durable read-back did not contain the expected SDK span")
			}
		})
	}
	for _, rejected := range []struct {
		name, credential string
		status           int
	}{{"missing", "", 401}, {"public-dsn", "Bearer " + config.PublicKey, 401}, {"read-only", "Bearer " + config.ReadToken, 403}} {
		t.Run(rejected.name, func(t *testing.T) {
			code, _ := h.post(t, "traces", []byte(`{}`), "application/json", "", rejected.credential)
			if code != rejected.status {
				t.Fatalf("Authorization status=%d expected=%d", code, rejected.status)
			}
		})
	}
	stats, err := h.store.Stats(context.Background())
	if err != nil {
		t.Fatal("Durable queue inspection failed")
	}
	for _, stream := range stats.Streams {
		if stream.Messages != 0 {
			t.Fatal("Unauthorized export reached durable admission")
		}
	}
	if strings.Contains(config.BackendSHA, " ") {
		t.Fatal("Invalid backend identity")
	}
	t.Logf("Verified real Rails authorization and encrypted admission: backend=%s SDK=1.46.0 HTTP+gRPC+gzip; signal persistence not evaluated", config.BackendSHA)
}

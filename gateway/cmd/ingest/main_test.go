package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bussolabs/closeyourit-ingest-community/gateway/internal/metrics"
)

func TestUpstreamTransportUsesPrivateDialOnlyForUpstream(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan struct{})
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr == nil {
			_ = connection.Close()
			close(accepted)
		}
	}()

	upstream, _ := url.Parse("https://bugs.example.com")
	transport := upstreamTransport(upstream, listener.Addr().String())
	connection, err := transport.DialContext(context.Background(), "tcp", "bugs.example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	_ = connection.Close()

	select {
	case <-accepted:
	case <-time.After(time.Second):
		t.Fatal("the private dial did not reach the configured address")
	}
}

func withSecrets(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	password := filepath.Join(dir, "nats_password")
	key := filepath.Join(dir, "envelope_key")
	if err := os.WriteFile(password, []byte("password-di-prova"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(key, []byte(base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{7}, 32))), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("NATS_PASSWORD_FILE", password)
	t.Setenv("ENVELOPE_KEY_FILE", key)
	t.Setenv("UPSTREAM_URL", "https://bugs.example.com")
}

func TestPlainHTTPUpstreamIsDialledOnTheDialAddress(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan struct{})
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr == nil {
			_ = connection.Close()
			close(accepted)
		}
	}()

	upstream, _ := url.Parse("http://bugs.example.com")
	transport := upstreamTransport(upstream, listener.Addr().String())
	connection, err := transport.DialContext(context.Background(), "tcp", "bugs.example.com:80")
	if err != nil {
		t.Fatal(err)
	}
	_ = connection.Close()

	select {
	case <-accepted:
	case <-time.After(time.Second):
		t.Fatal("the plain HTTP upstream was not dialled on the dial address")
	}
}

func TestConfigRefusesAMissingUpstream(t *testing.T) {
	withSecrets(t)
	t.Setenv("UPSTREAM_URL", "")

	if _, err := loadConfig(); err == nil {
		t.Fatal("a gateway without UPSTREAM_URL must not start")
	}
}

func TestMetricsListenOnAPortSeparateFromPublicTraffic(t *testing.T) {
	withSecrets(t)

	config, err := loadConfig()
	if err != nil {
		t.Fatal(err)
	}

	if config.metricsListenAddress != ":9101" {
		t.Fatalf("metrics_listen=%q", config.metricsListenAddress)
	}
	if config.metricsListenAddress == config.listenAddress {
		t.Fatal("the metrics must not share the listener served by Caddy")
	}
}

func TestMetricsAddressIsConfigurable(t *testing.T) {
	withSecrets(t)
	t.Setenv("METRICS_LISTEN_ADDRESS", "127.0.0.1:9999")

	config, err := loadConfig()
	if err != nil {
		t.Fatal(err)
	}

	if config.metricsListenAddress != "127.0.0.1:9999" {
		t.Fatalf("metrics_listen=%q", config.metricsListenAddress)
	}
}

func TestMetricsListenerDoesNotAcceptTelemetry(t *testing.T) {
	handler := metricsHandler(metrics.New())

	scrape := httptest.NewRecorder()
	handler.ServeHTTP(scrape, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	ingest := httptest.NewRecorder()
	handler.ServeHTTP(ingest, httptest.NewRequest(http.MethodPost, "/api/v1/projects/p/logs", strings.NewReader("[]")))

	if scrape.Code != http.StatusOK || !strings.Contains(scrape.Body.String(), "ingest_build_info") {
		t.Fatalf("scrape status=%d body=%q", scrape.Code, scrape.Body.String())
	}
	if ingest.Code != http.StatusNotFound {
		t.Fatalf("the metrics listener accepted telemetry: status=%d", ingest.Code)
	}
}

func TestObserveLoopUpdatesImmediatelyAndStopsWithTheContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	observations := make(chan struct{}, 4)
	done := make(chan struct{})

	go func() {
		observeLoop(ctx, time.Millisecond, func() { observations <- struct{}{} })
		close(done)
	}()

	select {
	case <-observations:
	case <-time.After(time.Second):
		t.Fatal("the loop observed nothing before the first tick")
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("the loop did not stop when the context was closed")
	}
}

func TestOTLPRemainsDisabledUnlessExplicitlyEnabled(t *testing.T) {
	withSecrets(t)
	t.Setenv("OTLP_ENABLED", "")
	config, err := loadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if config.otlpEnabled || config.otlpHTTPAddress != "127.0.0.1:4318" || config.otlpGRPCAddress != "127.0.0.1:4317" {
		t.Fatal("OTLP must default to disabled with private listeners")
	}
	t.Setenv("OTLP_ENABLED", "true")
	config, err = loadConfig()
	if err != nil {
		t.Fatal(err)
	}
	if !config.otlpEnabled {
		t.Fatal("Explicit OTLP configuration was ignored")
	}
}

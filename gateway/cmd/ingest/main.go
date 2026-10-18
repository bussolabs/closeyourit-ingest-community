package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/bussolabs/closeyourit-ingest-community/gateway/internal/cryptor"
	"github.com/bussolabs/closeyourit-ingest-community/gateway/internal/delivery"
	"github.com/bussolabs/closeyourit-ingest-community/gateway/internal/gateway"
	"github.com/bussolabs/closeyourit-ingest-community/gateway/internal/metrics"
	"github.com/bussolabs/closeyourit-ingest-community/gateway/internal/natsstore"
	"github.com/bussolabs/closeyourit-ingest-community/gateway/internal/otlp"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	if err := run(logger); err != nil && !errors.Is(err, context.Canceled) {
		logger.Error("ingest stopped", "error", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	config, err := loadConfig()
	if err != nil {
		return err
	}
	c, err := cryptor.New(config.envelopeKey)
	if err != nil {
		return fmt.Errorf("configure envelope encryption: %w", err)
	}
	recorder := metrics.New()

	natsConnection, err := nats.Connect(config.natsURL,
		nats.UserInfo(config.natsUser, config.natsPassword),
		nats.Name("closeyourit-ingest-gateway"),
		nats.Timeout(5*time.Second),
		nats.MaxReconnects(-1),
		nats.ReconnectWait(2*time.Second),
		nats.DisconnectErrHandler(func(_ *nats.Conn, err error) {
			recorder.RecordNATSDisconnect()
			logger.Warn("NATS disconnected", "error", err)
		}),
		nats.ReconnectHandler(func(_ *nats.Conn) {
			recorder.RecordNATSReconnect()
			logger.Info("NATS reconnected")
		}),
	)
	if err != nil {
		return fmt.Errorf("connect NATS: %w", err)
	}
	defer natsConnection.Close()

	js, err := jetstream.New(natsConnection)
	if err != nil {
		return fmt.Errorf("create JetStream client: %w", err)
	}
	setupContext, cancelSetup := context.WithTimeout(context.Background(), 15*time.Second)
	store, err := natsstore.Setup(setupContext, js)
	cancelSetup()
	if err != nil {
		return err
	}

	transport := upstreamTransport(config.upstream, config.upstreamDialAddress)
	directClient := &http.Client{Transport: transport, Timeout: config.proxyTimeout, CheckRedirect: noRedirect}
	deliveryClient := &http.Client{Transport: transport, Timeout: config.deliveryTimeout, CheckRedirect: noRedirect}
	handler := gateway.NewHandler(config.upstream, directClient, store, c, logger)
	handler.SetQueueConnectedFunc(natsConnection.IsConnected)
	handler.SetRecorder(recorder)
	rateLimiter := gateway.NewRateLimiter(config.rateLimit, time.Minute)
	rateLimiter.SetRecorder(recorder)
	limitedHandler := rateLimiter.Middleware(handler)

	server := &http.Server{
		Addr: config.listenAddress, Handler: limitedHandler,
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second,
		WriteTimeout: 20 * time.Second, IdleTimeout: 60 * time.Second,
	}
	// The metrics have their own listener, not published by Caddy: who can
	// read the health of the ingest is the private network, not the Internet.
	metricsServer := &http.Server{
		Addr: config.metricsListenAddress, Handler: metricsHandler(recorder),
		ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second,
		WriteTimeout: 20 * time.Second, IdleTimeout: 60 * time.Second,
	}
	worker := delivery.NewWorker(store, store, c, config.upstream, deliveryClient, logger)
	worker.SetRecorder(recorder)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	errCh := make(chan error, 4)
	var otlpReceiver *otlp.Receiver
	if config.otlpEnabled {
		otlpReceiver, err = otlp.NewPipeline(ctx, otlp.Config{HTTPAddress: config.otlpHTTPAddress, GRPCAddress: config.otlpGRPCAddress},
			otlp.RemoteAuthorizer{Upstream: config.upstream, Client: directClient},
			&otlp.DurableExporter{Publisher: store, Cryptor: c, Recorder: recorder})
		if err != nil {
			return err
		}
		if err = otlpReceiver.Start(ctx, nil); err != nil {
			return err
		}
		defer func() {
			shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			_ = otlpReceiver.Shutdown(shutdownCtx)
		}()
		go func() {
			select {
			case err := <-otlpReceiver.Errors:
				errCh <- err
			case <-ctx.Done():
			}
		}()
	}
	go func() {
		logger.Info("HTTP gateway started", "listen", config.listenAddress, "upstream", config.upstream.Host)
		errCh <- server.ListenAndServe()
	}()
	go func() {
		logger.Info("Prometheus metrics exposed", "listen", config.metricsListenAddress)
		errCh <- metricsServer.ListenAndServe()
	}()
	go func() { errCh <- worker.Run(ctx, config.deliveryConcurrency) }()
	go observeLoop(ctx, metrics.DefaultObserveInterval, func() {
		handler.RefreshReadiness()
		recorder.RefreshStats(ctx, store)
	})

	select {
	case <-ctx.Done():
	case err := <-errCh:
		if err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, context.Canceled) {
			stop()
			return err
		}
	}

	// Draining is declared right before closing: whoever polls
	// /ready during shutdown reads "draining" instead of an opaque error.
	// It is not a gapless handoff: the gateway is single-instance, so
	// waiting here for Caddy to notice would produce guaranteed 502s while the
	// process is still able to serve. The restart window is closed with
	// a second replica, not with a wait.
	handler.BeginShutdown()
	shutdownContext, cancelShutdown := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelShutdown()
	if otlpReceiver != nil {
		_ = otlpReceiver.Shutdown(shutdownContext)
	}
	_ = server.Shutdown(shutdownContext)
	_ = metricsServer.Shutdown(shutdownContext)
	_ = natsConnection.Drain()
	return ctx.Err()
}

type config struct {
	otlpEnabled          bool
	otlpHTTPAddress      string
	otlpGRPCAddress      string
	listenAddress        string
	metricsListenAddress string
	upstream             *url.URL
	natsURL              string
	natsUser             string
	natsPassword         string
	envelopeKey          string
	proxyTimeout         time.Duration
	deliveryTimeout      time.Duration
	deliveryConcurrency  int
	rateLimit            int
	upstreamDialAddress  string
}

func loadConfig() (config, error) {
	// No default: a self-hosted gateway must point at its own app, never at someone else's (CYRA-919).
	upstream, err := url.Parse(strings.TrimSpace(os.Getenv("UPSTREAM_URL")))
	if err != nil || upstream.Scheme == "" || upstream.Host == "" {
		return config{}, errors.New("invalid UPSTREAM_URL")
	}
	natsPassword, err := readSecret("NATS_PASSWORD_FILE")
	if err != nil {
		return config{}, err
	}
	envelopeKey, err := readSecret("ENVELOPE_KEY_FILE")
	if err != nil {
		return config{}, err
	}
	return config{
		otlpEnabled:          os.Getenv("OTLP_ENABLED") == "true",
		otlpHTTPAddress:      envOr("OTLP_HTTP_LISTEN_ADDRESS", "127.0.0.1:4318"),
		otlpGRPCAddress:      envOr("OTLP_GRPC_LISTEN_ADDRESS", "127.0.0.1:4317"),
		listenAddress:        envOr("LISTEN_ADDRESS", ":8080"),
		metricsListenAddress: envOr("METRICS_LISTEN_ADDRESS", ":9101"),
		upstream:             upstream,
		upstreamDialAddress:  strings.TrimSpace(os.Getenv("UPSTREAM_DIAL_ADDRESS")),
		natsURL:              envOr("NATS_URL", "nats://nats:4222"), natsUser: envOr("NATS_USER", "ingest"),
		natsPassword: natsPassword, envelopeKey: envelopeKey,
		proxyTimeout:        durationEnv("PROXY_TIMEOUT", 3*time.Second),
		deliveryTimeout:     durationEnv("DELIVERY_TIMEOUT", 15*time.Second),
		deliveryConcurrency: intEnv("DELIVERY_CONCURRENCY", 4), rateLimit: intEnv("RATE_LIMIT_PER_MINUTE", 600),
	}, nil
}

func readSecret(envName string) (string, error) {
	path := strings.TrimSpace(os.Getenv(envName))
	if path == "" {
		return "", fmt.Errorf("%s obbligatorio", envName)
	}
	value, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("read %s: %w", envName, err)
	}
	trimmed := strings.TrimSpace(string(value))
	if trimmed == "" {
		return "", fmt.Errorf("%s vuoto", envName)
	}
	return trimmed, nil
}

func envOr(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

func durationEnv(name string, fallback time.Duration) time.Duration {
	value, err := time.ParseDuration(os.Getenv(name))
	if err != nil || value <= 0 {
		return fallback
	}
	return value
}

func intEnv(name string, fallback int) int {
	value, err := strconv.Atoi(os.Getenv(name))
	if err != nil || value <= 0 {
		return fallback
	}
	return value
}

// metricsHandler serves the scrape and nothing else: client telemetry does not
// come in through this port, so the gateway's metrics never end up in the
// gateway.
func metricsHandler(recorder *metrics.Recorder) http.Handler {
	mux := http.NewServeMux()
	mux.Handle("GET /metrics", recorder.Handler())
	return mux
}

// observeLoop updates the metrics that no request touches: the queue depth
// and the state of the two paths would otherwise stay at the last
// value read, precisely while the service silently degrades.
func observeLoop(ctx context.Context, interval time.Duration, observe func()) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		observe()
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func noRedirect(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }

func upstreamTransport(upstream *url.URL, dialAddress string) *http.Transport {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if dialAddress == "" {
		return transport
	}
	upstreamAddress := upstream.Host
	if _, _, err := net.SplitHostPort(upstreamAddress); err != nil {
		// A self-hosted gateway talks plain HTTP to the app container next to it (CYRA-919).
		port := "443"
		if upstream.Scheme == "http" {
			port = "80"
		}
		upstreamAddress = net.JoinHostPort(upstream.Hostname(), port)
	}
	dialer := &net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		if address == upstreamAddress {
			address = dialAddress
		}
		return dialer.DialContext(ctx, network, address)
	}
	return transport
}

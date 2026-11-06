// Command worker scans stored files for personal data: it takes scan requests from
// the SQS queue the API sends them to, reads and decrypts each object from S3 in
// memory, and reports the kinds and counts of what it found to the API's internal
// scanner routes (see internal/worker).
//
// Configuration, from the environment:
//
//	VAULTGATE_SCAN_QUEUE_URL         SQS queue of scan requests (required)
//	VAULTGATE_API_INTERNAL_URL       the API's internal port (default http://localhost:8001)
//	VAULTGATE_SCANNER_TOKEN          secret for the internal scanner routes (required)
//	VAULTGATE_API_CLIENT_CERT_FILE, VAULTGATE_API_CLIENT_KEY_FILE
//	                                 the scanner's client certificate for that port, when it
//	                                 wants one (mutual TLS), reloaded when renewed
//	VAULTGATE_SECRETS_DIR            where credentials may come from instead, as files named
//	                                 after their variables in lower case (vaultgate_scanner_token)
//	VAULTGATE_BUCKET                 vault bucket (default vaultgate-local-vault)
//	VAULTGATE_AWS_REGION             default ap-northeast-1
//	VAULTGATE_AWS_ENDPOINT_URL       LocalStack locally; unset in AWS
//	VAULTGATE_SCANNER_CONCURRENCY    files scanned at once (default 2)
//	VAULTGATE_SCAN_TIMEOUT_SECONDS   longest one scan may take (default 600)
//	VAULTGATE_SCAN_VISIBILITY_SECONDS  how long a message in progress stays hidden
//	                                 from other workers, renewed while it runs (default 120)
//	VAULTGATE_METRICS_PORT           /metrics and /healthz (default 9100)
//	VAULTGATE_TLS_CERT_FILE, VAULTGATE_TLS_KEY_FILE
//	                                 serve that port over TLS with this certificate, reloaded
//	                                 when renewed (internal/tlsreload); unset, plain HTTP
//	VAULTGATE_LOG_LEVEL              default info
//	OTEL_EXPORTER_OTLP_ENDPOINT      where traces go over OTLP/HTTP (e.g. http://alloy:4318);
//	                                 unset, nothing is recorded (internal/tracing)
//
// SIGTERM or SIGINT stops receiving; scans in progress finish first.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/flaviocavalcantet/vaultgate/scanner/internal/extract"
	"github.com/flaviocavalcantet/vaultgate/scanner/internal/logging"
	"github.com/flaviocavalcantet/vaultgate/scanner/internal/tlsreload"
	"github.com/flaviocavalcantet/vaultgate/scanner/internal/tracing"
	"github.com/flaviocavalcantet/vaultgate/scanner/internal/worker"
)

const version = "0.1.0"

func main() {
	logger := logging.New(os.Stderr, os.Getenv("VAULTGATE_LOG_LEVEL"))
	if err := run(logger); err != nil {
		logger.Error("worker stopped", "error", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger) error {
	queueURL := os.Getenv("VAULTGATE_SCAN_QUEUE_URL")
	token := secret("VAULTGATE_SCANNER_TOKEN")
	if queueURL == "" || token == "" {
		return errors.New("VAULTGATE_SCAN_QUEUE_URL and VAULTGATE_SCANNER_TOKEN are required")
	}
	concurrency, err := intEnv("VAULTGATE_SCANNER_CONCURRENCY", 2)
	if err != nil {
		return err
	}
	timeout, err := intEnv("VAULTGATE_SCAN_TIMEOUT_SECONDS", 600)
	if err != nil {
		return err
	}
	visibility, err := intEnv("VAULTGATE_SCAN_VISIBILITY_SECONDS", 120)
	if err != nil {
		return err
	}
	metricsPort, err := intEnv("VAULTGATE_METRICS_PORT", 9100)
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, os.Interrupt)
	defer stop()
	cfg, err := config.LoadDefaultConfig(ctx, config.WithRegion(env("VAULTGATE_AWS_REGION", "ap-northeast-1")))
	if err != nil {
		return err
	}
	endpoint := os.Getenv("VAULTGATE_AWS_ENDPOINT_URL")
	if endpoint != "" {
		cfg.BaseEndpoint = aws.String(endpoint)
	}

	tracer, stopTracing, err := tracing.Setup(ctx, version)
	if err != nil {
		return err
	}
	defer func() {
		// Spans still buffered are sent before exit, within a bound.
		sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := stopTracing(sctx); err != nil {
			logger.Warn("flushing traces failed", "error", err)
		}
	}()

	// One PDF engine instance per concurrent scan, each capped in memory and time.
	pdf, err := extract.NewPDFium(concurrency, 512<<20, time.Minute)
	if err != nil {
		return err
	}
	defer pdf.Close()

	prometheus.MustRegister(prometheus.NewGaugeFunc(prometheus.GaugeOpts{
		Name:        "vaultgate_build_info",
		Help:        "Service build information",
		ConstLabels: prometheus.Labels{"service": "scanner", "version": version},
	}, func() float64 { return 1 }))
	api := worker.NewHTTPAPI(env("VAULTGATE_API_INTERNAL_URL", "http://localhost:8001"), token)
	api.Tracer = tracer
	clientCert, clientKey := os.Getenv("VAULTGATE_API_CLIENT_CERT_FILE"), os.Getenv("VAULTGATE_API_CLIENT_KEY_FILE")
	if (clientCert == "") != (clientKey == "") {
		return errors.New("set both VAULTGATE_API_CLIENT_CERT_FILE and VAULTGATE_API_CLIENT_KEY_FILE, or neither")
	}
	if clientCert != "" {
		clientReloader, err := tlsreload.New(clientCert, clientKey, logger)
		if err != nil {
			return err
		}
		transport := http.DefaultTransport.(*http.Transport).Clone()
		transport.TLSClientConfig = clientReloader.ClientConfig()
		api.Client.Transport = transport
		go clientReloader.Run(ctx, time.Minute)
	}
	w := &worker.Worker{
		API: api,
		Objects: &worker.S3Objects{
			Client: s3.NewFromConfig(cfg, func(o *s3.Options) { o.UsePathStyle = endpoint != "" }),
			Bucket: env("VAULTGATE_BUCKET", "vaultgate-local-vault"),
		},
		Keys:      &worker.KMSKeys{Client: kms.NewFromConfig(cfg)},
		Extractor: &extract.Extractor{Limits: extract.DefaultLimits(), PDF: pdf},
		Logger:    logger,
		Metrics:   worker.NewMetrics(prometheus.DefaultRegisterer),
		Tracer:    tracer,
	}
	loop := &worker.Loop{
		Worker:      w,
		Queue:       &worker.SQSQueue{Client: sqs.NewFromConfig(cfg), URL: queueURL},
		Concurrency: concurrency,
		Visibility:  time.Duration(visibility) * time.Second,
		JobTimeout:  time.Duration(timeout) * time.Second,
	}

	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok\n")) })
	server := &http.Server{Addr: fmt.Sprintf(":%d", metricsPort), Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	certFile, keyFile := os.Getenv("VAULTGATE_TLS_CERT_FILE"), os.Getenv("VAULTGATE_TLS_KEY_FILE")
	if (certFile == "") != (keyFile == "") {
		return errors.New("set both VAULTGATE_TLS_CERT_FILE and VAULTGATE_TLS_KEY_FILE, or neither")
	}
	if certFile != "" {
		reloader, err := tlsreload.New(certFile, keyFile, logger)
		if err != nil {
			return err
		}
		server.TLSConfig = reloader.ServerConfig()
		go reloader.Run(ctx, time.Minute)
	}
	go func() {
		var err error
		if server.TLSConfig != nil {
			err = server.ListenAndServeTLS("", "") // the certificate comes from TLSConfig
		} else {
			err = server.ListenAndServe()
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			logger.Error("metrics server stopped", "error", err)
		}
	}()
	defer server.Close()

	logger.Info("worker started", "concurrency", concurrency, "version", version)
	loop.Run(ctx)
	logger.Info("worker stopped receiving; scans in progress finished")
	return nil
}

func env(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

// secret is a credential: the variable, or else the file named after it in lower case
// in VAULTGATE_SECRETS_DIR, where credentials arrive from OpenBao on the cluster (M9, ADR
// 0012) on a memory-backed volume rather than in the environment.
func secret(name string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	dir := os.Getenv("VAULTGATE_SECRETS_DIR")
	if dir == "" {
		return ""
	}
	data, err := os.ReadFile(filepath.Join(dir, strings.ToLower(name))) // #nosec G304 G703 -- the operator's directory, a fixed name
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func intEnv(name string, fallback int) (int, error) {
	v := os.Getenv(name)
	if v == "" {
		return fallback, nil
	}
	n, err := strconv.Atoi(v)
	if err != nil || n < 1 {
		return 0, fmt.Errorf("%s must be a positive integer, got %q", name, v)
	}
	return n, nil
}

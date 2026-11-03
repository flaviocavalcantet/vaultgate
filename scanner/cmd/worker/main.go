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
//	VAULTGATE_BUCKET                 vault bucket (default vaultgate-local-vault)
//	VAULTGATE_AWS_REGION             default ap-northeast-1
//	VAULTGATE_AWS_ENDPOINT_URL       LocalStack locally; unset in AWS
//	VAULTGATE_SCANNER_CONCURRENCY    files scanned at once (default 2)
//	VAULTGATE_SCAN_TIMEOUT_SECONDS   longest one scan may take (default 600)
//	VAULTGATE_SCAN_VISIBILITY_SECONDS  how long a message in progress stays hidden
//	                                 from other workers, renewed while it runs (default 120)
//	VAULTGATE_METRICS_PORT           /metrics and /healthz (default 9100)
//	VAULTGATE_LOG_LEVEL              default info
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
	"strconv"
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
	token := os.Getenv("VAULTGATE_SCANNER_TOKEN")
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
	w := &worker.Worker{
		API: worker.NewHTTPAPI(env("VAULTGATE_API_INTERNAL_URL", "http://localhost:8001"), token),
		Objects: &worker.S3Objects{
			Client: s3.NewFromConfig(cfg, func(o *s3.Options) { o.UsePathStyle = endpoint != "" }),
			Bucket: env("VAULTGATE_BUCKET", "vaultgate-local-vault"),
		},
		Keys:      &worker.KMSKeys{Client: kms.NewFromConfig(cfg)},
		Extractor: &extract.Extractor{Limits: extract.DefaultLimits(), PDF: pdf},
		Logger:    logger,
		Metrics:   worker.NewMetrics(prometheus.DefaultRegisterer),
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
	go func() {
		if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
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

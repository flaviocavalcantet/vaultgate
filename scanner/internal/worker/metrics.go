package worker

import "github.com/prometheus/client_golang/prometheus"

// Metrics are the worker's Prometheus metrics.
type Metrics struct {
	jobs        *prometheus.CounterVec
	duration    prometheus.Histogram
	textBytes   prometheus.Counter
	inProgress  prometheus.Gauge
	queueErrors *prometheus.CounterVec
}

// NewMetrics registers the worker's metrics with reg.
func NewMetrics(reg prometheus.Registerer) *Metrics {
	m := &Metrics{
		jobs: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "vaultgate_scanner_jobs_total",
			Help: "Scan requests handled, by outcome (clean, quarantined, unscannable, stale, retry, invalid)",
		}, []string{"outcome"}),
		duration: prometheus.NewHistogram(prometheus.HistogramOpts{
			Name:    "vaultgate_scanner_job_duration_seconds",
			Help:    "Time to handle one scan request, from receiving it to reporting the result",
			Buckets: []float64{0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60, 120, 300, 600},
		}),
		textBytes: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "vaultgate_scanner_text_bytes_total",
			Help: "Bytes of extracted text run through the detectors",
		}),
		inProgress: prometheus.NewGauge(prometheus.GaugeOpts{
			Name: "vaultgate_scanner_jobs_in_progress",
			Help: "Scan requests being handled now",
		}),
		queueErrors: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "vaultgate_scanner_queue_errors_total",
			Help: "Failed queue calls, by operation (receive, delete, extend)",
		}, []string{"op"}),
	}
	reg.MustRegister(m.jobs, m.duration, m.textBytes, m.inProgress, m.queueErrors)
	return m
}

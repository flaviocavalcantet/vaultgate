package worker

import (
	"context"
	"sync"
	"time"

	"go.opentelemetry.io/otel/propagation"

	"github.com/flaviocavalcantet/vaultgate/scanner/internal/tracing"
)

// Delivery is one received message.
type Delivery struct {
	Body   string
	Handle string // receipt handle, for deleting it or extending its visibility
	// Trace is the sender's trace context (traceparent, tracestate), if it sent one.
	Trace map[string]string
}

// Queue is where scan requests come from.
type Queue interface {
	// Receive waits (long polling) for up to max messages; it may return none.
	Receive(ctx context.Context, max int) ([]Delivery, error)
	Delete(ctx context.Context, d Delivery) error
	// Extend keeps a message invisible to other consumers for another visibility.
	Extend(ctx context.Context, d Delivery, visibility time.Duration) error
}

// Loop runs the worker over a queue.
type Loop struct {
	Worker      *Worker
	Queue       Queue
	Concurrency int
	// While a message is being handled, its visibility is extended by this much,
	// every third of it, so no other worker receives it. Keep the queue's own
	// visibility timeout at least this long.
	Visibility time.Duration
	// Longest one message may take; past it, reads fail and the message is retried.
	JobTimeout time.Duration
}

// Run receives and handles messages until ctx is done, then waits for the messages
// in progress to finish (they are not cancelled by ctx: their own timeout bounds them).
func (l *Loop) Run(ctx context.Context) {
	slots := make(chan struct{}, l.Concurrency)
	var wg sync.WaitGroup
	defer wg.Wait()
	backoff := time.Second
	for {
		select { // wait for a free slot
		case slots <- struct{}{}:
		case <-ctx.Done():
			return
		}
		free := 1
	fill:
		for free < min(l.Concurrency, 10) { // SQS returns at most 10 at once
			select {
			case slots <- struct{}{}:
				free++
			default:
				break fill
			}
		}
		deliveries, err := l.Queue.Receive(ctx, free)
		for range free - len(deliveries) {
			<-slots
		}
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			l.Worker.Metrics.queueErrors.WithLabelValues("receive").Inc()
			l.Worker.Logger.Warn("receiving scan requests failed", "error", err, "retry_in", backoff.String())
			select {
			case <-time.After(backoff):
			case <-ctx.Done():
			}
			backoff = min(2*backoff, 30*time.Second)
			continue
		}
		backoff = time.Second
		for _, d := range deliveries {
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer func() { <-slots }()
				l.process(context.WithoutCancel(ctx), d)
			}()
		}
	}
}

func (l *Loop) process(ctx context.Context, d Delivery) {
	ctx, cancel := context.WithTimeout(ctx, l.JobTimeout)
	defer cancel()
	stop := make(chan struct{})
	heartbeat := sync.WaitGroup{}
	heartbeat.Add(1)
	go func() {
		defer heartbeat.Done()
		tick := time.NewTicker(l.Visibility / 3)
		defer tick.Stop()
		for {
			select {
			case <-stop:
				return
			case <-tick.C:
				if err := l.Queue.Extend(ctx, d, l.Visibility); err != nil {
					l.Worker.Metrics.queueErrors.WithLabelValues("extend").Inc()
					l.Worker.Logger.Warn("extending a message's visibility failed", "error", err)
				}
			}
		}
	}()
	outcome := l.Worker.Handle(tracing.Propagator.Extract(ctx, propagation.MapCarrier(d.Trace)), d.Body)
	close(stop)
	heartbeat.Wait()
	if !outcome.Done() {
		return // delivered again once its visibility runs out
	}
	// A fresh context: the job's may have run out, and an undeleted message is only
	// handled again (and found stale), so this is worth a few seconds.
	dctx, dcancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer dcancel()
	if err := l.Queue.Delete(dctx, d); err != nil {
		l.Worker.Metrics.queueErrors.WithLabelValues("delete").Inc()
		l.Worker.Logger.Warn("deleting a handled message failed", "error", err)
	}
}

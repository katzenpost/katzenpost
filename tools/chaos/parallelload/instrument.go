// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package parallelload

import (
	"net/http"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var registerOnce sync.Once

var (
	iterationsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "katzenpost_parallel_load_iterations_total",
			Help: "Pigeonhole write/read iterations completed by the parallel-load tool, by client and result.",
		},
		[]string{"client_id", "result"},
	)
	iterationLatency = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "katzenpost_parallel_load_iteration_seconds",
			Help:    "Wall-clock duration of a pigeonhole write-then-read iteration, by operation.",
			Buckets: []float64{0.5, 1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024},
		},
		[]string{"op"},
	)
	activeClients = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "katzenpost_parallel_load_active_clients",
			Help: "Number of concurrent thin clients currently driving load.",
		},
	)
	sweepStep = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "katzenpost_parallel_load_sweep_step_clients",
			Help: "Current sweep step expressed as offered concurrency (number of concurrent thin clients).",
		},
	)
	errorsByKind = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "katzenpost_parallel_load_errors_total",
			Help: "Errors during a pigeonhole iteration, by stage and kind.",
		},
		[]string{"stage", "kind"},
	)
)

// StartListener registers the metrics and starts the HTTP listener on
// the given address (empty disables the listener).
func StartListener(address string) {
	registerOnce.Do(func() {
		prometheus.MustRegister(iterationsTotal)
		prometheus.MustRegister(iterationLatency)
		prometheus.MustRegister(activeClients)
		prometheus.MustRegister(sweepStep)
		prometheus.MustRegister(errorsByKind)
	})
	if address != "" {
		http.Handle("/metrics", promhttp.Handler())
		go http.ListenAndServe(address, nil)
	}
}

// IterationCompleted records a successful iteration and its full cycle
// duration. clientID is a stable per-goroutine label.
func IterationCompleted(clientID string, cycle time.Duration) {
	iterationsTotal.With(prometheus.Labels{"client_id": clientID, "result": "ok"}).Inc()
	iterationLatency.With(prometheus.Labels{"op": "cycle"}).Observe(cycle.Seconds())
}

// IterationFailed records a failed iteration with a stage and kind.
func IterationFailed(clientID, stage, kind string) {
	iterationsTotal.With(prometheus.Labels{"client_id": clientID, "result": "error"}).Inc()
	errorsByKind.With(prometheus.Labels{"stage": stage, "kind": kind}).Inc()
}

// OperationLatency records the duration of one sub-operation (write,
// read, copy) within an iteration.
func OperationLatency(op string, d time.Duration) {
	iterationLatency.With(prometheus.Labels{"op": op}).Observe(d.Seconds())
}

// SetActiveClients sets the current concurrent-client gauge.
func SetActiveClients(n int) {
	activeClients.Set(float64(n))
}

// SetSweepStep sets the current sweep step gauge.
func SetSweepStep(n int) {
	sweepStep.Set(float64(n))
}

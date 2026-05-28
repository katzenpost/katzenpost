// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package cpbench

import (
	"net/http"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var registerOnce sync.Once

var (
	runsTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "katzenpost_cp_bench_runs_total",
			Help: "Number of completed pigeonhole-cp benchmark runs by result.",
		},
		[]string{"result"},
	)
	totalSeconds = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "katzenpost_cp_bench_total_seconds",
			Help:    "Wall-clock duration of one full pigeonhole-cp benchmark cycle from temp-channel writes through Copy command terminal status, by labelled payload size.",
			Buckets: []float64{1, 5, 10, 30, 60, 120, 300, 600, 1200, 2400},
		},
		[]string{"payload_bytes"},
	)
	bytesPerSec = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "katzenpost_cp_bench_bytes_per_second",
			Help: "End-to-end useful bytes/sec achieved by the most recent pigeonhole-cp benchmark run, labelled by payload size. Useful as the headline throughput number to compare across Sphinx geometries.",
		},
		[]string{"payload_bytes"},
	)
	chunksObserved = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "katzenpost_cp_bench_chunks_per_payload",
			Help: "Number of copy-stream chunks produced for the given payload size by CreateCourierEnvelopesFromPayload. A function of Sphinx geometry; falls as UserForwardPayloadLength rises.",
		},
		[]string{"payload_bytes"},
	)
	errorsByStage = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "katzenpost_cp_bench_errors_total",
			Help: "Errors during pigeonhole-cp benchmark, by stage.",
		},
		[]string{"stage"},
	)
)

// StartListener registers and exposes the cp-bench metric surface.
// Safe to call multiple times; registration and listener startup
// happen exactly once.
func StartListener(address string) {
	registerOnce.Do(func() {
		prometheus.MustRegister(runsTotal)
		prometheus.MustRegister(totalSeconds)
		prometheus.MustRegister(bytesPerSec)
		prometheus.MustRegister(chunksObserved)
		prometheus.MustRegister(errorsByStage)
		if address == "" {
			return
		}
		http.Handle("/metrics", promhttp.Handler())
		go http.ListenAndServe(address, nil)
	})
}

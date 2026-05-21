// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

//go:build kpclientd_metrics

// Package instrument provides prometheus instrumentation for the
// kpclientd client daemon. Built only when the kpclientd_metrics build
// tag is set, so production binaries compile out the listener, the
// dependency on prometheus/client_golang, and the metric definitions
// entirely. The companion file noop.go provides stubs for the
// !kpclientd_metrics build, so callers may invoke these functions
// unconditionally.
//
// Privacy posture: this instrumentation is intended only for the docker
// mixnet and other operator-controlled debugging environments. The
// listener binds to 127.0.0.1 by default and the metric set is
// deliberately aggregate-only: no labels by recipient, box ID, contact,
// or courier choice are exposed.
package instrument

import (
	"net/http"
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var registerOnce sync.Once

var (
	lambdaPFifoPop = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "katzenpost_client_lambdap_fifo_pop_total",
			Help: "Real messages popped from the per-client FIFO and emitted on a LambdaP tick.",
		},
	)
	lambdaPDecoy = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "katzenpost_client_lambdap_decoy_total",
			Help: "Loop decoys emitted on a LambdaP tick when the FIFO was empty.",
		},
	)
	lambdaLDecoy = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "katzenpost_client_lambdal_decoy_total",
			Help: "Loop decoys emitted by the independent LambdaL ticker.",
		},
	)
	sendQueueDepth = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "katzenpost_client_send_queue_depth",
			Help: "Current depth of the aggregate client send FIFO across all connected thin clients.",
		},
	)
	arqInflight = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "katzenpost_client_arq_inflight",
			Help: "Number of ARQ entries currently awaiting a reply.",
		},
	)
	gatewayConnected = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "katzenpost_client_gateway_connected",
			Help: "Whether the client daemon currently believes it is connected to its gateway (0 or 1).",
		},
	)
	pkiDocAgeSeconds = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "katzenpost_client_pki_doc_age_seconds",
			Help: "Age in seconds of the most recently cached PKI document.",
		},
	)
	arqRoundTrip = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "katzenpost_client_arq_round_trip_seconds",
			Help:    "End-to-end ARQ round-trip latency: send to acknowledgement.",
			Buckets: prometheus.ExponentialBuckets(0.05, 2, 12),
		},
	)
	surbIDCreated = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "katzenpost_client_surb_id_created_total",
			Help: "Number of SURB IDs created for ARQ entries.",
		},
	)
	surbIDGarbageCollected = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "katzenpost_client_surb_id_garbage_collected_total",
			Help: "Number of SURB IDs removed from the ARQ map due to TTL expiry or session cleanup rather than reply receipt.",
		},
	)
	surbIDReplyReceived = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "katzenpost_client_surb_id_reply_received_total",
			Help: "Number of ARQ replies received whose SURB ID matched an awaiting entry.",
		},
	)
	surbIDReplyNoMatch = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "katzenpost_client_surb_id_reply_no_match_total",
			Help: "Number of ARQ replies received whose SURB ID was not in the awaiting map. Either the reply was garbage-collected before arrival, the reply was misrouted, or the SURB ID matching itself is buggy. This counter is the diagnostic for the reply-routing problem.",
		},
	)
	thinSessions = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "katzenpost_client_thin_sessions",
			Help: "Current count of registered thin-client sessions.",
		},
	)
)

// StartPrometheusListener registers metrics and starts the HTTP listener
// if address is non-empty. Safe to call multiple times; registration
// happens exactly once and subsequent listener starts after the first
// are ignored. Binds to whatever address the caller supplies; convention
// in this project is to use 127.0.0.1 only.
func StartPrometheusListener(address string) {
	registerOnce.Do(func() {
		prometheus.MustRegister(lambdaPFifoPop)
		prometheus.MustRegister(lambdaPDecoy)
		prometheus.MustRegister(lambdaLDecoy)
		prometheus.MustRegister(sendQueueDepth)
		prometheus.MustRegister(arqInflight)
		prometheus.MustRegister(gatewayConnected)
		prometheus.MustRegister(pkiDocAgeSeconds)
		prometheus.MustRegister(arqRoundTrip)
		prometheus.MustRegister(surbIDCreated)
		prometheus.MustRegister(surbIDGarbageCollected)
		prometheus.MustRegister(surbIDReplyReceived)
		prometheus.MustRegister(surbIDReplyNoMatch)
		prometheus.MustRegister(thinSessions)
	})
	if address == "" {
		return
	}
	http.Handle("/metrics", promhttp.Handler())
	go http.ListenAndServe(address, nil)
}

// LambdaPFifoPop records one real-message emission on a LambdaP tick.
func LambdaPFifoPop() { lambdaPFifoPop.Inc() }

// LambdaPDecoy records one fallback loop-decoy emission on a LambdaP
// tick when the FIFO was empty.
func LambdaPDecoy() { lambdaPDecoy.Inc() }

// LambdaLDecoy records one loop-decoy emission from the LambdaL ticker.
func LambdaLDecoy() { lambdaLDecoy.Inc() }

// SendQueueEnqueue increments the aggregate send-queue depth gauge.
// Pair with SendQueueDequeue on the drain side.
func SendQueueEnqueue() { sendQueueDepth.Inc() }

// SendQueueDequeue decrements the aggregate send-queue depth gauge.
func SendQueueDequeue() { sendQueueDepth.Dec() }

// ARQInflightSet sets the current ARQ in-flight count.
func ARQInflightSet(n int) { arqInflight.Set(float64(n)) }

// GatewayConnected records the daemon's view of its gateway link state.
func GatewayConnected(connected bool) {
	if connected {
		gatewayConnected.Set(1)
		return
	}
	gatewayConnected.Set(0)
}

// PKIDocFetched records that a fresh PKI document has just been cached;
// the gauge will report the age of the document monotonically until the
// next call.
func PKIDocFetched(at time.Time) {
	pkiDocAgeSeconds.Set(time.Since(at).Seconds())
}

// ARQRoundTrip observes a completed ARQ round-trip latency.
func ARQRoundTrip(d time.Duration) {
	arqRoundTrip.Observe(d.Seconds())
}

// SurbIDCreated records the creation of a new SURB ID for an ARQ entry.
func SurbIDCreated() { surbIDCreated.Inc() }

// SurbIDGarbageCollected records the removal of a SURB ID due to TTL
// expiry or session cleanup, distinct from removal due to a successful
// reply.
func SurbIDGarbageCollected() { surbIDGarbageCollected.Inc() }

// SurbIDReplyReceived records an ARQ reply whose SURB ID matched an
// awaiting entry.
func SurbIDReplyReceived() { surbIDReplyReceived.Inc() }

// SurbIDReplyNoMatch records an ARQ reply whose SURB ID was not in the
// awaiting map. This is the data-driven diagnostic for the reply-routing
// problem we suspected during the recent ping investigation.
func SurbIDReplyNoMatch() { surbIDReplyNoMatch.Inc() }

// ThinSessionsSet sets the current count of registered thin-client
// sessions. Pass len(listener.conns) after each register/unregister.
func ThinSessionsSet(n int) { thinSessions.Set(float64(n)) }

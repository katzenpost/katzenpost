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
	surbIDReplyMatched = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "katzenpost_client_surb_id_reply_matched_total",
			Help: "Number of ARQ replies received whose SURB ID matched an awaiting entry in arqSurbIDMap. A match is NOT itself an exit from the map: the entry stays alive until the downstream handler either rotates it (Rotated), errors it out, or deletes it on terminal success (Delivered). Pair this counter with reply_no_match_total to diagnose lost replies, and with delivered_total to see what fraction of matches went on to a delivered outcome.",
		},
	)
	surbIDDelivered = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "katzenpost_client_surb_id_delivered_total",
			Help: "Number of SURB IDs that exited arqSurbIDMap via a terminal success path: ARQActionComplete (Write ACK), CopyStatusSucceeded, payloadActionIdempotentSuccess, or the post-payload-handling cleanup after a successful read. This is one of the four exit counters whose sum should equal created_total at steady state (the others are Rotated, GarbageCollected, and the error-deletes which are not yet counted).",
		},
	)
	surbIDReplyNoMatch = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "katzenpost_client_surb_id_reply_no_match_total",
			Help: "Number of ARQ replies received whose SURB ID was not in the awaiting map. Either the reply was garbage-collected before arrival, the reply was misrouted, or the SURB ID matching itself is buggy. This counter is the diagnostic for the reply-routing problem.",
		},
	)
	surbIDRotated = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "katzenpost_client_surb_id_rotated_total",
			Help: "Number of times an existing ARQ map entry's SURB ID was replaced by a new one (ACK-before-payload Copy command flows, compose-retry placeholders, Copy-status-poll placeholders). The old SURB ID exits the map without firing any of reply_received, garbage_collected, or reply_no_match; rotated_total is the missing exit counter that closes the lifecycle balance with created_total.",
		},
	)
	thinSessions = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "katzenpost_client_thin_sessions",
			Help: "Current count of registered thin-client sessions.",
		},
	)
	disconnectedSessions = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "katzenpost_client_disconnected_sessions",
			Help: "Number of thin-client sessions whose underlying connection has dropped without thin_close and whose state is being preserved in case the client reconnects within the grace period.",
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
		prometheus.MustRegister(surbIDReplyMatched)
		prometheus.MustRegister(surbIDDelivered)
		prometheus.MustRegister(surbIDReplyNoMatch)
		prometheus.MustRegister(surbIDRotated)
		prometheus.MustRegister(thinSessions)
		prometheus.MustRegister(disconnectedSessions)
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

// SurbIDReplyMatched records an ARQ reply whose SURB ID matched an
// awaiting entry in arqSurbIDMap. This is a match indicator only, NOT
// an exit from the map: the downstream handler will either rotate the
// entry to a fresh SURB (SurbIDRotated), error it out (currently
// uncounted), or delete it on terminal success (SurbIDDelivered).
func SurbIDReplyMatched() { surbIDReplyMatched.Inc() }

// SurbIDDelivered records the exit of a SURB ID from arqSurbIDMap via
// a terminal-success delete: ARQActionComplete (Write ACK),
// CopyStatusSucceeded, payloadActionIdempotentSuccess, or the
// post-payload-handling cleanup after a successful read. The lifecycle
// balance is: created = delivered + rotated + garbage_collected +
// (uncounted error/cancel deletes). See instrument/prometheus.go for
// the rationale on which exit each delete site belongs to.
func SurbIDDelivered() { surbIDDelivered.Inc() }

// SurbIDReplyNoMatch records an ARQ reply whose SURB ID was not in the
// awaiting map. This is the data-driven diagnostic for the reply-routing
// problem we suspected during the recent ping investigation.
func SurbIDReplyNoMatch() { surbIDReplyNoMatch.Inc() }

// SurbIDRotated records the exit of an old SURB ID from the ARQ map
// via rotation: a new SURB ID replaces it for the next retransmission
// (ACK-before-payload Copy command flows, compose-retry placeholders,
// Copy-status-poll placeholders). Pair with SurbIDCreated at the
// matching insertion site to keep the lifecycle balanced.
func SurbIDRotated() { surbIDRotated.Inc() }

// ThinSessionsSet sets the current count of registered thin-client
// sessions. Pass len(listener.conns) after each register/unregister.
func ThinSessionsSet(n int) { thinSessions.Set(float64(n)) }

// DisconnectedSessionsSet sets the current count of disconnected
// thin-client sessions whose per-app state is being preserved
// pending a possible reconnect. Pass len(listener.disconnectedSessions)
// after each insert into or delete from that map.
func DisconnectedSessionsSet(n int) { disconnectedSessions.Set(float64(n)) }

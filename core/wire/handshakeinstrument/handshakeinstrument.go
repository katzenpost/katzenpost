// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

//go:build !noprometheus
// +build !noprometheus

// Package handshakeinstrument exports a uniform Prometheus surface for PQ
// Noise wire-protocol handshake outcomes across every Katzenpost binary
// that performs handshakes: mix / gateway / service nodes, replicas,
// directory authorities, the courier, and kpclientd. The metric names
// and label schema are identical regardless of role; Prometheus
// aggregates the per-role counts via the standard {instance, job} scrape
// labels so a single dashboard panel can show handshake outcomes for the
// whole network or any one role.
//
// init() registers the metrics with the default Prometheus registerer
// so any binary that imports this package automatically exposes the
// counters and histograms via its own /metrics endpoint, without any
// per-component registration code.
package handshakeinstrument

import (
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	handshakeFailures = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "katzenpost_handshake_failures_total",
			Help: "Number of PQ Noise handshake attempts that failed, labelled by direction (incoming/outgoing) and the wire-protocol state at which the failure was observed (e.g. message_2_receive, peer_authentication, premature_close). Use the state label to distinguish slow-PQ-KEM timeouts from PKI rollover misses from connection-reset cases. Emitted by every role that performs PQ Noise handshakes: mix/gateway/service nodes, replicas, directory authorities, the courier, and kpclientd. Operators filter by job or instance label to scope to one role.",
		},
		[]string{"direction", "state"},
	)
	handshakeDurationSeconds = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "katzenpost_handshake_duration_seconds",
			Help:    "Wall-clock duration of a PQ Noise handshake attempt, labelled by direction (incoming/outgoing) and result (success/failure). Success samples bound the realistic PQ-KEM cost on this host; failure samples sit at or just above the configured HandshakeTimeout when a timeout was the cause.",
			Buckets: prometheus.ExponentialBuckets(0.05, 2, 12),
		},
		[]string{"direction", "result"},
	)
	incomingPeerValidationFailures = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "katzenpost_incoming_peer_validation_failures_total",
			Help: "Number of times the responder side of a wire handshake rejected the initiator at the Authenticator callback (after Noise msg3, before msg4). Pairs operationally with katzenpost_handshake_failures_total{direction=\"outgoing\",state=\"message_4_receive\"} on the initiator's side: a rise on both at once is the diagnostic signature of asymmetric PKI propagation, i.e. the initiator has a fresh enough view of the responder but the responder has not yet ingested the initiator's descriptor.",
		},
		[]string{"reason"},
	)
	incomingRefusedNoPKIDoc = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "katzenpost_incoming_refused_no_pki_doc_total",
			Help: "Number of accepted TCP connections the listener immediately closed because no PKI document had been loaded yet. Without a document the responder cannot validate any peer; attempting Noise would produce spurious handshake failures on the initiator side. This counter should grow only during the startup convergence window (before the first PKI doc is fetched) and then stay flat in steady state. Sustained growth in steady state would indicate the daemon is missing its current-epoch document and may be falling behind on consensus.",
		},
	)
	outgoingDialFailures = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "katzenpost_outgoing_dial_failures_total",
			Help: "Number of outbound TCP dial attempts that failed before any Noise handshake could begin, labelled by reason (refused, timeout, no_route, dns, other). These never produce a handshake_failures_total counter increment because the wire.Session.Initialize call site is never reached; this counter is the only operator surface for pre-handshake dial failures.",
		},
		[]string{"reason"},
	)
)

func init() {
	prometheus.MustRegister(handshakeFailures)
	prometheus.MustRegister(handshakeDurationSeconds)
	prometheus.MustRegister(incomingPeerValidationFailures)
	prometheus.MustRegister(incomingRefusedNoPKIDoc)
	prometheus.MustRegister(outgoingDialFailures)
}

// HandshakeFailure increments the failure counter for a PQ Noise
// handshake attempt. direction is "incoming" or "outgoing"; state
// is one of the wire.HandshakeState values plus the synthetic
// "premature_close" for the TCP-closed-before-bytes case and
// "other" for anything else.
func HandshakeFailure(direction, state string) {
	handshakeFailures.With(prometheus.Labels{"direction": direction, "state": state}).Inc()
}

// HandshakeDuration observes the wall-clock time of a handshake
// attempt. direction is "incoming" or "outgoing"; result is
// "success" or "failure".
func HandshakeDuration(direction, result string, d time.Duration) {
	handshakeDurationSeconds.With(prometheus.Labels{"direction": direction, "result": result}).Observe(d.Seconds())
}

// IncomingPeerValidationFailure increments the responder-side
// counter for handshakes the daemon rejected at the Authenticator
// callback. reason classifies the rejection, e.g. "unknown_mix",
// "client_dropped_from_userdb", "unknown_peer".
func IncomingPeerValidationFailure(reason string) {
	incomingPeerValidationFailures.With(prometheus.Labels{"reason": reason}).Inc()
}

// IncomingRefusedNoPKIDoc increments the counter for connections
// the listener refused at TCP accept because no PKI document was
// loaded.
func IncomingRefusedNoPKIDoc() {
	incomingRefusedNoPKIDoc.Inc()
}

// OutgoingDialFailure increments the counter for TCP dial attempts
// that failed before any Noise handshake could begin. reason is a
// short stable token from {"refused", "timeout", "no_route", "dns",
// "other"}.
func OutgoingDialFailure(reason string) {
	outgoingDialFailures.With(prometheus.Labels{"reason": reason}).Inc()
}

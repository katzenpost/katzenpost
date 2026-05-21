// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

//go:build !noprometheus

// Package instrument provides prometheus instrumentation for the
// Katzenpost voting directory authority. The dirauth previously had
// no metrics surface at all; voting progress, descriptor
// accept/reject, consensus achievement, and peer connectivity were
// observable only via logs.
//
// The metric surface here mirrors the shape of
// replica/instrument/prometheus.go and server/internal/instrument/
// prometheus.go: a registry-once block of metric definitions, a
// sync.Once-guarded StartPrometheusListener that registers the metrics
// and serves /metrics, and a flat list of accessor functions called
// from the dirauth code (state.go, wire_handler.go, server.go).
//
// The companion build-tag-gated file prometheus_dummy.go provides
// matching no-op stubs for the noprometheus build.
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
	votesReceived = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "katzenpost_dirauth_votes_received_total",
			Help: "Number of votes received from peer dirauths, labelled by validation result (ok, not_authorized, too_early, too_late, already_received, not_signed, malformed).",
		},
		[]string{"result"},
	)
	descriptorsAccepted = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "katzenpost_dirauth_descriptors_accepted_total",
			Help: "Number of node descriptor uploads accepted, labelled by kind (mix or replica).",
		},
		[]string{"kind"},
	)
	descriptorsRejected = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "katzenpost_dirauth_descriptors_rejected_total",
			Help: "Number of node descriptor uploads rejected, labelled by kind and reason. Reasons map to the existing rejection branches in wire_handler.go.",
		},
		[]string{"kind", "reason"},
	)
	consensusReached = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "katzenpost_dirauth_consensus_reached_total",
			Help: "Number of epochs for which threshold consensus has been reached by this dirauth.",
		},
	)
	peerSendAttempt = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "katzenpost_dirauth_peer_send_attempt_total",
			Help: "Number of attempts to send a command to a peer dirauth, labelled by peer identifier and result (ok, permanent_error, transient_error, deadline_exceeded).",
		},
		[]string{"peer", "result"},
	)
	votingPhase = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "katzenpost_dirauth_voting_phase",
			Help: "Current voting FSM phase encoded as an integer: 0=bootstrap, 1=accept_descriptor, 2=accept_vote, 3=accept_reveal, 4=accept_cert, 5=accept_signature.",
		},
	)
	peerConnected = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "katzenpost_dirauth_peer_connected",
			Help: "1 when the most recent send to the named peer dirauth succeeded, 0 when it failed permanently.",
		},
		[]string{"peer"},
	)
	currentEpoch = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "katzenpost_dirauth_current_epoch",
			Help: "The voting epoch currently being processed by the FSM.",
		},
	)
	documentGeneration = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "katzenpost_dirauth_document_generation_seconds",
			Help:    "Wall-clock time to build a consensus PKI document from votes, descriptors, and topology.",
			Buckets: prometheus.DefBuckets,
		},
	)
)

// phaseToInt maps the string-constant FSM phase to the integer encoding
// used by the votingPhase gauge. Unknown phases yield -1 so an
// unrecognised state is visible on the dashboard rather than silently
// folded into bootstrap.
func phaseToInt(phase string) float64 {
	switch phase {
	case "bootstrap":
		return 0
	case "accept_desc":
		return 1
	case "accept_vote":
		return 2
	case "accept_reveal":
		return 3
	case "accept_cert":
		return 4
	case "accept_signature":
		return 5
	default:
		return -1
	}
}

// StartPrometheusListener registers the dirauth metrics and starts the
// HTTP listener if address is non-empty. Safe to call multiple times;
// registration happens exactly once.
func StartPrometheusListener(address string) {
	registerOnce.Do(func() {
		prometheus.MustRegister(votesReceived)
		prometheus.MustRegister(descriptorsAccepted)
		prometheus.MustRegister(descriptorsRejected)
		prometheus.MustRegister(consensusReached)
		prometheus.MustRegister(peerSendAttempt)
		prometheus.MustRegister(votingPhase)
		prometheus.MustRegister(peerConnected)
		prometheus.MustRegister(currentEpoch)
		prometheus.MustRegister(documentGeneration)
	})
	if address == "" {
		return
	}
	http.Handle("/metrics", promhttp.Handler())
	go http.ListenAndServe(address, nil)
}

// VoteReceived increments the per-result vote counter.
func VoteReceived(result string) {
	votesReceived.With(prometheus.Labels{"result": result}).Inc()
}

// DescriptorAccepted increments the per-kind accept counter.
func DescriptorAccepted(kind string) {
	descriptorsAccepted.With(prometheus.Labels{"kind": kind}).Inc()
}

// DescriptorRejected increments the per-kind, per-reason reject counter.
func DescriptorRejected(kind, reason string) {
	descriptorsRejected.With(prometheus.Labels{"kind": kind, "reason": reason}).Inc()
}

// ConsensusReached increments the consensus-achievement counter.
func ConsensusReached() {
	consensusReached.Inc()
}

// PeerSendAttempt increments the per-peer, per-result counter.
func PeerSendAttempt(peer, result string) {
	peerSendAttempt.With(prometheus.Labels{"peer": peer, "result": result}).Inc()
}

// VotingPhase records the current FSM phase. Pass the string-constant
// value used by state.go (e.g. "accept_vote"); the mapping to the
// integer gauge is internal.
func VotingPhase(phase string) {
	votingPhase.Set(phaseToInt(phase))
}

// PeerConnected sets the per-peer connection-state gauge.
func PeerConnected(peer string, connected bool) {
	v := 0.0
	if connected {
		v = 1.0
	}
	peerConnected.With(prometheus.Labels{"peer": peer}).Set(v)
}

// CurrentEpoch sets the gauge tracking the FSM's current voting epoch.
func CurrentEpoch(epoch uint64) {
	currentEpoch.Set(float64(epoch))
}

// DocumentGenerated observes the wall-clock time to build a consensus
// document.
func DocumentGenerated(d time.Duration) {
	documentGeneration.Observe(d.Seconds())
}

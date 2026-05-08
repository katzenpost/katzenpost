// SPDX-FileCopyrightText: Copyright (C) 2025 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

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
	incomingDecoysReceived = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "katzenpost_replica_incoming_decoys_received_total",
			Help: "Number of decoy commands received from couriers",
		},
	)
	incomingDecoyRepliesEmitted = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "katzenpost_replica_incoming_decoy_replies_emitted_total",
			Help: "Number of decoy replies (responses to peer decoys) emitted by the delayed-reply scheduler on incoming connections.",
		},
	)
	incomingRealRepliesEmitted = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "katzenpost_replica_incoming_real_replies_emitted_total",
			Help: "Number of real replies (ReplicaWriteReply, ReplicaMessageReply) emitted by the delayed-reply scheduler on incoming connections.",
		},
	)
	incomingRealReplyLatency = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "katzenpost_replica_incoming_real_reply_latency_seconds",
			Help:    "Wall-clock latency from inbound real-command receipt to outbound real-reply emission on incoming connections (i.e. processing time plus the per-reply uniform jitter).",
			Buckets: prometheus.DefBuckets,
		},
	)
	incomingDecoyReplyLatency = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "katzenpost_replica_incoming_decoy_reply_latency_seconds",
			Help:    "Wall-clock latency from inbound peer-decoy receipt to outbound decoy-reply emission on incoming connections (i.e. processing time plus the per-reply uniform jitter).",
			Buckets: prometheus.DefBuckets,
		},
	)
	incomingQueueLength = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "katzenpost_replica_incoming_queue_length",
			Help: "Current queue depth per courier connection",
		},
		[]string{"peer"},
	)
	replicationDispatched = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "katzenpost_replica_replication_dispatched_total",
			Help: "Number of replication commands dispatched to other replicas",
		},
	)
	replicationLatency = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "katzenpost_replica_replication_latency_seconds",
			Help:    "Time from replication dispatch to completion, including semaphore wait",
			Buckets: prometheus.DefBuckets,
		},
	)
	outgoingQueueLength = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "katzenpost_replica_outgoing_queue_length",
			Help: "Current outgoing queue depth per replica connection",
		},
		[]string{"peer"},
	)
	outgoingDecoysSent = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "katzenpost_replica_outgoing_decoys_sent_total",
			Help: "Number of decoy commands sent to other replicas",
		},
	)
	outgoingMessagesSent = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "katzenpost_replica_outgoing_messages_sent_total",
			Help: "Number of real commands sent to other replicas",
		},
	)
	retryQueueSize = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "katzenpost_replica_retry_queue_size",
			Help: "Current number of pending replication retries across all peers",
		},
	)
	retryQueueDropped = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "katzenpost_replica_retry_queue_dropped_total",
			Help: "Number of pending replication retries evicted from the queue",
		},
		[]string{"reason"},
	)
)

// StartPrometheusListener registers metrics and starts the HTTP listener
// if address is non-empty.
func StartPrometheusListener(address string) {
	registerOnce.Do(func() {
		prometheus.MustRegister(incomingDecoysReceived)
		prometheus.MustRegister(incomingDecoyRepliesEmitted)
		prometheus.MustRegister(incomingRealRepliesEmitted)
		prometheus.MustRegister(incomingRealReplyLatency)
		prometheus.MustRegister(incomingDecoyReplyLatency)
		prometheus.MustRegister(incomingQueueLength)
		prometheus.MustRegister(replicationDispatched)
		prometheus.MustRegister(replicationLatency)
		prometheus.MustRegister(outgoingQueueLength)
		prometheus.MustRegister(outgoingDecoysSent)
		prometheus.MustRegister(outgoingMessagesSent)
		prometheus.MustRegister(retryQueueSize)
		prometheus.MustRegister(retryQueueDropped)
	})

	if address != "" {
		http.Handle("/metrics", promhttp.Handler())
		go http.ListenAndServe(address, nil)
	}
}

// IncomingDecoysReceived increments the counter for decoy commands received from couriers
func IncomingDecoysReceived() {
	incomingDecoysReceived.Inc()
}

// IncomingDecoyReplyEmitted increments the counter for decoy replies
// (responses to peer decoys) emitted on incoming connections, and
// records the per-reply latency.
func IncomingDecoyReplyEmitted(latency time.Duration) {
	incomingDecoyRepliesEmitted.Inc()
	incomingDecoyReplyLatency.Observe(latency.Seconds())
}

// IncomingRealReplyEmitted increments the counter for real replies
// (ReplicaWriteReply, ReplicaMessageReply) emitted on incoming
// connections, and records the per-reply latency.
func IncomingRealReplyEmitted(latency time.Duration) {
	incomingRealRepliesEmitted.Inc()
	incomingRealReplyLatency.Observe(latency.Seconds())
}

// IncomingQueueLength sets the incoming queue depth gauge for a peer
func IncomingQueueLength(peer string, length int) {
	incomingQueueLength.With(prometheus.Labels{"peer": peer}).Set(float64(length))
}

// ReplicationDispatched increments the counter for replication commands dispatched
func ReplicationDispatched() {
	replicationDispatched.Inc()
}

// ReplicationLatency observes the duration of a replication operation
func ReplicationLatency(seconds float64) {
	replicationLatency.Observe(seconds)
}

// OutgoingQueueLength sets the outgoing queue depth gauge for a peer
func OutgoingQueueLength(peer string, length int) {
	outgoingQueueLength.With(prometheus.Labels{"peer": peer}).Set(float64(length))
}

// OutgoingDecoysSent increments the counter for decoy commands sent to other replicas
func OutgoingDecoysSent() {
	outgoingDecoysSent.Inc()
}

// OutgoingMessagesSent increments the counter for real commands sent to other replicas
func OutgoingMessagesSent() {
	outgoingMessagesSent.Inc()
}

// RetryQueueSize sets the gauge for the current retry queue depth.
func RetryQueueSize(size int) {
	retryQueueSize.Set(float64(size))
}

// RetryQueueDropped increments the drop counter with the given reason label
// ("capacity" or "ttl").
func RetryQueueDropped(reason string) {
	retryQueueDropped.With(prometheus.Labels{"reason": reason}).Inc()
}

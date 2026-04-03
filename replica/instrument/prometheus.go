// SPDX-FileCopyrightText: Copyright (C) 2025 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package instrument

import (
	"net/http"
	"sync"

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
	incomingDecoysSent = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "katzenpost_replica_incoming_decoys_sent_total",
			Help: "Number of decoy responses sent back to couriers",
		},
	)
	incomingMessagesSent = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "katzenpost_replica_incoming_messages_sent_total",
			Help: "Number of real responses sent back to couriers",
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
)

// StartPrometheusListener registers metrics and starts the HTTP listener
// if address is non-empty.
func StartPrometheusListener(address string) {
	registerOnce.Do(func() {
		prometheus.MustRegister(incomingDecoysReceived)
		prometheus.MustRegister(incomingDecoysSent)
		prometheus.MustRegister(incomingMessagesSent)
		prometheus.MustRegister(incomingQueueLength)
		prometheus.MustRegister(replicationDispatched)
		prometheus.MustRegister(replicationLatency)
		prometheus.MustRegister(outgoingQueueLength)
		prometheus.MustRegister(outgoingDecoysSent)
		prometheus.MustRegister(outgoingMessagesSent)
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

// IncomingDecoysSent increments the counter for decoy responses sent back to couriers
func IncomingDecoysSent() {
	incomingDecoysSent.Inc()
}

// IncomingMessagesSent increments the counter for real responses sent back to couriers
func IncomingMessagesSent() {
	incomingMessagesSent.Inc()
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

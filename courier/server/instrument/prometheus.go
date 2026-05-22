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
	decoysSent = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "katzenpost_courier_decoys_sent_total",
			Help: "Number of decoy messages sent to replicas",
		},
	)
	messagesSent = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "katzenpost_courier_messages_sent_total",
			Help: "Number of real messages sent to replicas",
		},
	)
	queueLength = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "katzenpost_courier_queue_length",
			Help: "Current queue depth per replica connection",
		},
		[]string{"replica"},
	)
	messagesReceived = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "katzenpost_courier_messages_received_total",
			Help: "Number of messages received from mix server",
		},
	)
	enqueueTotal = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "katzenpost_courier_enqueue_total",
			Help: "Number of messages enqueued per replica connection. Pair with messages_sent_total to detect items that are enqueued but not drained.",
		},
		[]string{"replica"},
	)
	processingDuration = prometheus.NewHistogramVec(
		prometheus.HistogramOpts{
			Name:    "katzenpost_courier_processing_duration_seconds",
			Help:    "Time from enqueue to dequeue for a real (non-decoy) message, per replica connection.",
			Buckets: prometheus.DefBuckets,
		},
		[]string{"replica"},
	)
	oldestAgeSeconds = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "katzenpost_courier_oldest_age_seconds",
			Help: "Age of the oldest message currently waiting in the per-replica queue. Sampled at each dequeue tick.",
		},
		[]string{"replica"},
	)
	peerConnected = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "katzenpost_courier_peer_connected",
			Help: "1 when the courier holds an established connection to the named replica, 0 otherwise.",
		},
		[]string{"replica"},
	)
	droppedReason = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "katzenpost_courier_dropped_reason_total",
			Help: "Number of messages dropped inside the courier, labelled by the specific drop site. Mirrors the server-side katzenpost_dropped_reason_total pattern.",
		},
		[]string{"reason"},
	)
	dispatchSemWaiters = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "katzenpost_courier_dispatch_sem_waiters",
			Help: "Number of replica-dispatch goroutines currently blocked acquiring a dispatchSem slot. Sustained values above zero indicate the hard-coded maxConcurrentReplicaDispatch cap (256) is acting as a constraint and a Courier.MaxConcurrentReplicaDispatch config field should be considered.",
		},
	)
	copyShardReadCompute = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "katzenpost_courier_copy_shard_read_compute_seconds",
			Help:    "Wall-clock time the courier itself spends on MKEM Encapsulate plus DecryptEnvelope during one per-shard Copy read. Pair with katzenpost_courier_copy_shard_read_total_seconds to derive the courier's CTIDH wait-to-compute ratio: W/C = (total - compute) / compute.",
			Buckets: prometheus.DefBuckets,
		},
	)
	copyShardReadTotal = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "katzenpost_courier_copy_shard_read_total_seconds",
			Help:    "Wall-clock from Encapsulate start to DecryptEnvelope end on a per-shard Copy read. Includes the courier's own CTIDH compute plus the replica round-trip (network plus the replica's own CTIDH). Only observed on the success path so every sample carries both an Encap and a Decap.",
			Buckets: prometheus.DefBuckets,
		},
	)
)

// StartPrometheusListener registers metrics and starts the HTTP listener
// if address is non-empty.
func StartPrometheusListener(address string) {
	registerOnce.Do(func() {
		prometheus.MustRegister(decoysSent)
		prometheus.MustRegister(messagesSent)
		prometheus.MustRegister(queueLength)
		prometheus.MustRegister(messagesReceived)
		prometheus.MustRegister(enqueueTotal)
		prometheus.MustRegister(processingDuration)
		prometheus.MustRegister(oldestAgeSeconds)
		prometheus.MustRegister(peerConnected)
		prometheus.MustRegister(droppedReason)
		prometheus.MustRegister(dispatchSemWaiters)
		prometheus.MustRegister(copyShardReadCompute)
		prometheus.MustRegister(copyShardReadTotal)
	})

	if address != "" {
		http.Handle("/metrics", promhttp.Handler())
		go http.ListenAndServe(address, nil)
	}
}

// DecoysSent increments the counter for decoy messages sent
func DecoysSent() {
	decoysSent.Inc()
}

// MessagesSent increments the counter for real messages sent
func MessagesSent() {
	messagesSent.Inc()
}

// QueueLength sets the queue depth gauge for a replica
func QueueLength(replica string, length int) {
	queueLength.With(prometheus.Labels{"replica": replica}).Set(float64(length))
}

// MessagesReceived increments the counter for messages received from mix server
func MessagesReceived() {
	messagesReceived.Inc()
}

// EnqueueTotal increments the enqueue counter for a replica connection.
// Pair with MessagesSent / DecoysSent for drain-vs-fill diagnostics.
func EnqueueTotal(replica string) {
	enqueueTotal.With(prometheus.Labels{"replica": replica}).Inc()
}

// ProcessingDuration observes the enqueue-to-dequeue dwell time for a
// real message on the per-replica queue. Decoys are not observed
// because they are synthesised at dequeue and have no enqueue site.
func ProcessingDuration(replica string, d time.Duration) {
	processingDuration.With(prometheus.Labels{"replica": replica}).Observe(d.Seconds())
}

// OldestAgeSeconds sets the per-replica oldest-pending-message age
// gauge. Called at dequeue time using the EnqueuedAt timestamp of the
// most-recently-popped request.
func OldestAgeSeconds(replica string, age time.Duration) {
	oldestAgeSeconds.With(prometheus.Labels{"replica": replica}).Set(age.Seconds())
}

// PeerConnected sets the per-replica connection-state gauge.
func PeerConnected(replica string, connected bool) {
	v := 0.0
	if connected {
		v = 1.0
	}
	peerConnected.With(prometheus.Labels{"replica": replica}).Set(v)
}

// DroppedByReason increments the per-reason drop counter.
func DroppedByReason(reason string) {
	droppedReason.With(prometheus.Labels{"reason": reason}).Inc()
}

// DispatchSemWaitStart marks the entry of a goroutine into the blocking
// dispatchSem acquire. Pair with DispatchSemWaitEnd on every exit path
// from the acquire select so the gauge tracks only currently-blocked
// goroutines and not steady-state ones holding a slot.
func DispatchSemWaitStart() {
	dispatchSemWaiters.Inc()
}

// DispatchSemWaitEnd marks the exit of a goroutine from the dispatchSem
// acquire select, whether the slot was obtained or the wait was cancelled
// by shutdown.
func DispatchSemWaitEnd() {
	dispatchSemWaiters.Dec()
}

// CopyShardReadCompute observes the per-shard Copy-read MKEM compute time
// (Encapsulate plus DecryptEnvelope), in seconds.
func CopyShardReadCompute(d time.Duration) {
	copyShardReadCompute.Observe(d.Seconds())
}

// CopyShardReadTotal observes the per-shard Copy-read wall-clock from
// Encapsulate start through DecryptEnvelope end, in seconds. Recorded only
// on the success path so every sample carries both a compute and a wait
// component.
func CopyShardReadTotal(d time.Duration) {
	copyShardReadTotal.Observe(d.Seconds())
}

// SPDX-FileCopyrightText: Copyright (C) 2025 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package instrument

import (
	"sync"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"gopkg.in/op/go-logging.v1"

	"github.com/katzenpost/katzenpost/common/metrics"
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
	replicaDroppedByReason = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "katzenpost_replica_dropped_reason_total",
			Help: "Number of commands or persisted records the replica dropped, labelled by the specific drop site. Mirrors the server-side katzenpost_dropped_reason_total pattern; counts events the retry queue does not see (e.g. nil command, permanent peer error, malformed persisted record).",
		},
		[]string{"reason"},
	)
	selfCheckOpsPerSecSolo = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "katzenpost_replica_selfcheck_ctidh_ops_per_sec_solo",
			Help: "MKEM (CTIDH1024-X25519) Decapsulate ops/sec measured by a single goroutine at startup: the best-case per-core throughput. Useful for a one-replica-per-machine deployment baseline. For a co-tenanted host, see the saturated gauge instead.",
		},
	)
	selfCheckOpsPerSecSaturated = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "katzenpost_replica_selfcheck_ctidh_ops_per_sec_saturated",
			Help: "MKEM (CTIDH1024-X25519) Decapsulate ops/sec measured at startup with runtime.NumCPU goroutines decapsulating concurrently: the realistic aggregate ceiling for this replica process when the host's cores are fully utilised. Ops teams running multiple replicas on one host should divide this number by the count of co-tenanted replicas to estimate the per-replica share.",
		},
	)
	selfCheckCores = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "katzenpost_replica_selfcheck_num_cpu",
			Help: "Cores reported by runtime.NumCPU at startup. Pair with the solo and saturated ops/sec gauges to reason about queue size and worker counts.",
		},
	)
	replicationSemWaiters = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "katzenpost_replica_replication_sem_waiters",
			Help: "Number of DispatchReplication goroutines currently blocked acquiring a replicationSem slot. The cap is the package-level const maxConcurrentReplications (256) in replica/connector.go. Sustained values above zero would indicate the cap is acting as a constraint and a config field should be reconsidered; in practice the bounded work is sub-millisecond per goroutine so this gauge should stay at zero. Sibling of katzenpost_courier_dispatch_sem_waiters on the courier side.",
		},
	)
	replicaReady = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "katzenpost_replica_ready",
			Help: "1 iff this replica's descriptor in the current consensus document carries the same per-replica-epoch envelope key this instance holds. 0 otherwise (including while booting or waiting for a current-epoch document).",
		},
	)
	replicaCurrentEpoch = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "katzenpost_replica_current_epoch",
			Help: "The replica epoch whose consensus the replica_ready gauge was last computed against.",
		},
	)
	proxySemWaiters = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "katzenpost_replica_proxy_sem_waiters",
			Help: "Number of proxied-request handlers currently blocked acquiring a proxySema slot. The cap is the ProxyWorkerCount config field, which defaults to runtime.NumCPU. Unlike the replication semaphore this one guards a network round-trip, so a slow shard holder parks slots for as long as it stays slow. Sustained values above zero while peers are alive mean proxying to healthy peers is queued behind a sick one.",
		},
	)
	proxyRequestLatency = prometheus.NewHistogram(
		prometheus.HistogramOpts{
			Name:    "katzenpost_replica_proxy_request_latency_seconds",
			Help:    "Wall-clock latency of a single proxied request to one shard holder, measured from dispatch to reply, timeout or fast-fail. One observation per candidate attempt, so a failover sweep records one per holder tried.",
			Buckets: prometheus.DefBuckets,
		},
	)
	proxyRequestTimedOut = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "katzenpost_replica_proxy_request_timeouts_total",
			Help: "Number of proxied requests that reached ProxyRequestTimeout without a reply, labelled by the shard holder that did not answer.",
		},
		[]string{"peer"},
	)
	proxyActiveAttempts = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "katzenpost_replica_proxy_active_attempts",
			Help: "Number of proxied-request attempts currently holding a proxySema slot. Read against katzenpost_replica_proxy_sem_waiters to tell saturation apart from queueing: active pinned at ProxyWorkerCount with waiters above zero means the pool is the constraint, while waiters above zero with active below the cap means slots are turning over and something else is slow.",
		},
	)
	proxyPendingRequests = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "katzenpost_replica_proxy_pending_requests",
			Help: "Number of proxied requests currently registered with the ProxyRequestManager awaiting a reply. Read alongside katzenpost_replica_proxy_sem_waiters: pending counts requests on the wire, waiters counts handlers that have not got that far.",
		},
	)
)

// StartPrometheusListener registers metrics and starts the HTTP listener
// if address is non-empty. Panics if a configured address cannot be
// bound.
func StartPrometheusListener(address string, log *logging.Logger) {
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
		prometheus.MustRegister(replicaDroppedByReason)
		prometheus.MustRegister(selfCheckOpsPerSecSolo)
		prometheus.MustRegister(selfCheckOpsPerSecSaturated)
		prometheus.MustRegister(selfCheckCores)
		prometheus.MustRegister(replicationSemWaiters)
		prometheus.MustRegister(replicaReady)
		prometheus.MustRegister(replicaCurrentEpoch)
		prometheus.MustRegister(proxySemWaiters)
		prometheus.MustRegister(proxyRequestLatency)
		prometheus.MustRegister(proxyRequestTimedOut)
		prometheus.MustRegister(proxyActiveAttempts)
		prometheus.MustRegister(proxyPendingRequests)
	})

	if address == "" {
		return
	}
	metrics.MustServe(address, log)
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

// DroppedByReason increments the per-reason replica drop counter. Use
// at any site where the replica discards a command or record outside
// the retry-queue path (which has its own RetryQueueDropped).
func DroppedByReason(reason string) {
	replicaDroppedByReason.With(prometheus.Labels{"reason": reason}).Inc()
}

// SelfCheckResults publishes the startup CTIDH self-check measurement
// to its prometheus gauges. opsPerSecSolo is the single-goroutine rate
// (best-case per-core); opsPerSecSaturated is the
// NumCPU-goroutines-in-parallel aggregate (realistic ceiling for one
// replica process when its host is busy); numCPU is the cores at
// startup. The two ops/sec numbers serve different audiences:
// per-machine deployments care about the solo number, co-tenanted
// deployments care about the saturated number.
func SelfCheckResults(opsPerSecSolo, opsPerSecSaturated float64, numCPU int) {
	selfCheckOpsPerSecSolo.Set(opsPerSecSolo)
	selfCheckOpsPerSecSaturated.Set(opsPerSecSaturated)
	selfCheckCores.Set(float64(numCPU))
}

// ReplicationSemWaitStart and ReplicationSemWaitEnd bracket the
// blocking acquire of the per-process replicationSem inside
// Connector.DispatchReplication (see replica/connector.go). The
// gauge tracks the number of goroutines currently parked on the
// semaphore. The bounded work after the slot is held is
// sub-millisecond, so this gauge should stay at zero in steady
// state; sustained positive values would mean the hard-coded
// maxConcurrentReplications const is the constraint and a
// configurable cap should be reconsidered.
func ReplicationSemWaitStart() {
	replicationSemWaiters.Inc()
}

// ReplicationSemWaitEnd marks exit from the acquire select (either
// slot obtained or shutdown).
func ReplicationSemWaitEnd() {
	replicationSemWaiters.Dec()
}

// SetReplicaReady sets the replica_ready gauge based on whether the
// descriptor this replica published in the current consensus carries the
// same per-replica-epoch envelope key this instance holds. Anything else
// (no current-epoch document cached, mismatched keys) is 0, so a restart
// is never reported ready until the consensus actually matches.
func SetReplicaReady(ready bool, epoch uint64) {
	if ready {
		replicaReady.Set(1)
	} else {
		replicaReady.Set(0)
	}
	replicaCurrentEpoch.Set(float64(epoch))
}

// ProxySemWaitStart and ProxySemWaitEnd bracket the blocking acquire
// of the per-process proxySema in replica/handlers.go.
//
// The pairing matters and is easy to break in a refactor: Start
// increments on entry to the acquire, and End decrements on EVERY exit
// from it, whether a slot was obtained or the server is shutting down.
// This gauge counts waiters, not holders. Holders are
// ProxyAttemptStart/End below, which bracket the slot itself. Unlike
// ReplicationSemWaitStart/End above, the work done under this
// semaphore is a network round-trip to a shard holder rather than a
// sub-millisecond dispatch, so a slow holder holds slots for as long
// as it stays slow. A sustained positive reading while peers are
// alive means proxied traffic to healthy holders is queued behind a
// sick one, and ProxyWorkerCount is the constraint.
func ProxySemWaitStart() {
	proxySemWaiters.Inc()
}

// ProxySemWaitEnd marks exit from the acquire select (either slot
// obtained or shutdown).
func ProxySemWaitEnd() {
	proxySemWaiters.Dec()
}

// ProxyRequestLatency observes the duration of one proxied-request
// attempt against a single shard holder, whether it ended in a reply,
// a timeout or a fast-fail. A failover sweep records one observation
// per holder tried.
func ProxyRequestLatency(d time.Duration) {
	proxyRequestLatency.Observe(d.Seconds())
}

// ProxyRequestTimedOut increments the per-peer counter for a proxied
// request that reached ProxyRequestTimeout with no reply.
func ProxyRequestTimedOut(peer string) {
	proxyRequestTimedOut.With(prometheus.Labels{"peer": peer}).Inc()
}

// ProxyPendingRequests sets the gauge for proxied requests currently
// registered with the ProxyRequestManager awaiting a reply.
func ProxyPendingRequests(n int) {
	proxyPendingRequests.Set(float64(n))
}

// ProxyAttemptStart and ProxyAttemptEnd bracket the holding of a
// proxySema slot, as distinct from waiting for one. Increment after a
// slot is obtained, decrement when it is released.
func ProxyAttemptStart() {
	proxyActiveAttempts.Inc()
}

// ProxyAttemptEnd marks the release of a proxySema slot.
func ProxyAttemptEnd() {
	proxyActiveAttempts.Dec()
}

//go:build !noprometheus
// +build !noprometheus

package instrument

import (
	"fmt"
	"net/http"

	"github.com/katzenpost/katzenpost/core/wire/commands"
	"github.com/katzenpost/katzenpost/server/internal/glue"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	incomingConns = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "katzenpost_incoming_requests_total",
			Help: "Number of incoming requests",
		},
		[]string{"command"},
	)
	outgoingConns = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "katzenpost_outgoing_connections_total",
			Help: "Number of outgoing connections",
		},
	)
	ingressQueueSize = prometheus.NewSummary(
		prometheus.SummaryOpts{
			Name: "katzenpost_ingress_queue_size",
			Help: "Size of the ingress queue",
		},
	)
	packetsDropped = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "katzenpost_dropped_packets_total",
			Help: "Number of dropped packets",
		},
	)
	outgoingPacketsDropped = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "katzenpost_dropped_outgoing_packets_total",
			Help: "Number of dropped packets",
		},
	)
	invalidPacketsDropped = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "katzenpost_dropped_invalid_packets_total",
			Help: "Number of dropped invalid packets",
		},
	)
	deadlineBlownPacketsDropped = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "katzenpost_dropped_deadline_blown_packets_total",
			Help: "Number of dropped deadline blown packets",
		},
	)
	packetsReplayed = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "katzenpost_replayed_packets_total",
			Help: "Number of replayed packets",
		},
	)
	ignoredPKIDocs = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "katzenpost_documents_ignored_total",
			Help: "Number of ignored PKI Documents",
		},
	)
	kaetzchenRequests = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "katzenpost_kaetzchen_requests_total",
			Help: "Number of Kaetzchen requests",
		},
	)
	kaetzchenRequestsDuration = prometheus.NewSummary(
		prometheus.SummaryOpts{
			Name: "katzenpost_kaetzchen_requests_duration_seconds",
			Help: "Duration of a kaetzchen request in seconds",
		},
	)
	kaetzchenPacketsDropped = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "katzenpost_kaetzchen_dropped_packets_total",
			Help: "Number of dropped kaetzchen packets",
		},
	)
	kaetzchenRequestsDropped = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "katzenpost_kaetzchen_dropped_requests_total",
			Help: "Number of total dropped kaetzchen requests",
		},
	)
	kaetzchenRequestsFailed = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "katzenpost_kaetzchen_failed_requests_total",
			Help: "Number of total failed kaetzchen requests",
		},
	)
	mixPacketsDropped = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "katzenpost_kaetzchen_mix_packets_dropped_total",
			Help: "Number of total dropped mixed packets",
		},
	)
	mixQueueSize = prometheus.NewSummary(
		prometheus.SummaryOpts{
			Name: "katzenpost_mix_queue_size",
			Help: "Size of the mix queue",
		},
	)
	pkiDocs = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "katzenpost_pki_docs_per_epoch_total",
			Help: "Number of pki docs in an epoch",
		},
		[]string{"epoch"},
	)
	cancelledOutgoingConns = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "katzenpost_cancelled_outgoing_connections_total",
			Help: "Number of cancelled outgoing connections",
		},
	)
	fetchedPKIDocs = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "katzenpost_fetched_pki_docs_per_epoch_total",
			Help: "Number of fetch PKI docs per epoch",
		},
		[]string{"epoch"},
	)
	fetchedPKIDocsDuration = prometheus.NewSummary(
		prometheus.SummaryOpts{
			Name: "katzenpost_fetched_pki_docs_per_epoch_duration",
			Help: "Duration of PKI docs fetching requests per epoch",
		},
	)
	failedFetchPKIDocs = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "katzenpost_failed_fetch_pki_docs_per_epoch_total",
			Help: "Number of failed PKI docs fetches per epoch",
		},
		[]string{"epoch"},
	)
	failedPKICacheGeneration = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "katzenpost_failed_pki_cache_generation_per_epoch_total",
			Help: "Number of failed PKI caches generation per epoch",
		},
		[]string{"epoch"},
	)
	invalidPKICache = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "katzenpost_invalid_pki_cache_per_epoch_total",
			Help: "Number of invalid PKI caches per epoch",
		},
		[]string{"epoch"},
	)
	channelUsage = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "katzenpost_channel_usage",
			Help: "Current number of items in the channel",
		},
		[]string{"channel_name"},
	)
	rateLimitDropped = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "katzenpost_dropped_rate_limit_total",
			Help: "Number of client packets dropped by the gateway's per-client token-bucket admission control. Sibling of katzenpost_dropped_packets_total; this counter isolates rate-limit drops from scheduler and validity drops.",
		},
	)
	sphinxUnwraps = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "katzenpost_sphinx_unwraps_total",
			Help: "Number of successful Sphinx unwrap operations performed by the crypto worker. The rate of this counter is the realised Sphinx throughput; compare against the BenchmarkSphinxUnwrap capacity reported by the host (paper Appendix V).",
		},
	)
	packetsDroppedByReason = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "katzenpost_dropped_reason_total",
			Help: "Packets dropped, broken down by the specific code path that discarded them. Fires alongside katzenpost_dropped_packets_total so the legacy aggregate counter stays consistent while the per-reason breakdown identifies which drop site is active.",
		},
		[]string{"reason"},
	)
	selfCheckSphinxOpsPerSecSolo = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "katzenpost_server_selfcheck_sphinx_ops_per_sec_solo",
			Help: "Sphinx Unwrap ops/sec measured by a single goroutine at startup: the best-case per-core throughput. Useful for a one-process-per-host deployment baseline. For a co-tenanted host, see the saturated gauge instead.",
		},
	)
	selfCheckSphinxOpsPerSecSaturated = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "katzenpost_server_selfcheck_sphinx_ops_per_sec_saturated",
			Help: "Sphinx Unwrap ops/sec measured at startup with runtime.NumCPU goroutines unwrapping concurrently: the realistic aggregate ceiling for this mix-server process when the host's cores are fully utilised. Ops teams running multiple katzenpost processes on one host should divide this number by the count of co-tenanted processes for the per-process share.",
		},
	)
	selfCheckSphinxCores = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "katzenpost_server_selfcheck_num_cpu",
			Help: "Cores reported by runtime.NumCPU at startup. Pair with the solo and saturated ops/sec gauges to reason about queue size and worker counts.",
		},
	)
	handshakeFailures = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "katzenpost_handshake_failures_total",
			Help: "Number of PQ Noise handshake attempts that failed, labelled by direction (incoming/outgoing) and the wire-protocol state at which the failure was observed (e.g. message_2_receive, peer_authentication, premature_close). Use the state label to distinguish slow-PQ-KEM timeouts from PKI rollover misses from connection-reset cases.",
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
)

// StartPrometheusListener starts the Prometheus metrics TCP/HTTP Listener
func StartPrometheusListener(glue glue.Glue) {
	prometheus.MustRegister(deadlineBlownPacketsDropped)
	prometheus.MustRegister(incomingConns)
	prometheus.MustRegister(invalidPacketsDropped)
	prometheus.MustRegister(outgoingConns)
	prometheus.MustRegister(ingressQueueSize)
	prometheus.MustRegister(outgoingPacketsDropped)
	prometheus.MustRegister(packetsDropped)
	prometheus.MustRegister(packetsReplayed)
	prometheus.MustRegister(ignoredPKIDocs)
	prometheus.MustRegister(kaetzchenRequests)
	prometheus.MustRegister(kaetzchenPacketsDropped)
	prometheus.MustRegister(kaetzchenRequestsDropped)
	prometheus.MustRegister(kaetzchenRequestsDuration)
	prometheus.MustRegister(kaetzchenRequestsFailed)
	prometheus.MustRegister(mixPacketsDropped)
	prometheus.MustRegister(mixQueueSize)
	prometheus.MustRegister(pkiDocs)
	prometheus.MustRegister(cancelledOutgoingConns)
	prometheus.MustRegister(fetchedPKIDocs)
	prometheus.MustRegister(fetchedPKIDocsDuration)
	prometheus.MustRegister(failedFetchPKIDocs)
	prometheus.MustRegister(failedPKICacheGeneration)
	prometheus.MustRegister(invalidPKICache)
	prometheus.MustRegister(channelUsage)
	prometheus.MustRegister(rateLimitDropped)
	prometheus.MustRegister(sphinxUnwraps)
	prometheus.MustRegister(packetsDroppedByReason)
	prometheus.MustRegister(selfCheckSphinxOpsPerSecSolo)
	prometheus.MustRegister(selfCheckSphinxOpsPerSecSaturated)
	prometheus.MustRegister(selfCheckSphinxCores)
	prometheus.MustRegister(handshakeFailures)
	prometheus.MustRegister(handshakeDurationSeconds)

	metricsAddress := glue.Config().Server.MetricsAddress
	if metricsAddress != "" {
		// Expose registered metrics via HTTP
		http.Handle("/metrics", promhttp.Handler())
		go http.ListenAndServe(metricsAddress, nil)
	}
}

// Incoming increments the counter for incoming requests
func Incoming(cmd commands.Command) {
	cmdStr := fmt.Sprintf("%T", cmd)
	incomingConns.With(prometheus.Labels{"command": cmdStr}).Inc()
}

// Outgoing increments the counter for outgoing connections
func Outgoing() {
	outgoingConns.Inc()
}

// IngressQueue observes the size of the ingress queue
func IngressQueue(size uint8) {
	ingressQueueSize.Observe(float64(size))
}

// PacketsDropped increments the counter for the number of packets dropped
func PacketsDropped() {
	packetsDropped.Inc()
}

// PacketsReplayed increments the counter for the number of replayed packets
func PacketsReplayed() {
	packetsReplayed.Inc()
}

// IgnoredPKIDocs increments the counter for the number of ignored PKI docs
func IgnoredPKIDocs() {
	ignoredPKIDocs.Inc()
}

// KaetzchenPacketsDropped increments the counter for the number of dropped Kaetzchen requests
func KaetzchenPacketsDropped() {
	kaetzchenPacketsDropped.Inc()
}

// KaetzchenRequests increments the counter for the number of kaetzchen requests
func KaetzchenRequests() {
	kaetzchenRequests.Inc()
}

// KaetzchenRequestsDropped increments the counter for the number of dropped kaetzchen requests
func KaetzchenRequestsDropped(dropCounter uint64) {
	kaetzchenRequestsDropped.Add(float64(dropCounter))
}

// KaetzchenRequestsFailed increments the counter for the number of failed kaetzchen requests
func KaetzchenRequestsFailed() {
	kaetzchenRequestsFailed.Inc()
}

// MixPacketsDropped increments the counter for the number of mix packets dropped
func MixPacketsDropped() {
	mixPacketsDropped.Inc()
}

// OutgoingPacketsDropped increments the counter for the number of packets dropped in the outgoing worker.
func OutgoingPacketsDropped() {
	outgoingPacketsDropped.Inc()
}

// DeadlineBlownPacketsDropped increments the counter for the number of packets dropped due to excessive dwell.
func DeadlineBlownPacketsDropped() {
	deadlineBlownPacketsDropped.Inc()
}

// InvalidPacketsDropped increments the counter for the number of invalid packets dropped.
func InvalidPacketsDropped() {
	invalidPacketsDropped.Inc()
}

// MixQueueSize observes the size of the mix queue
func MixQueueSize(size uint64) {
	mixQueueSize.Observe(float64(size))
}

// PKIDocs increments the counter for the number of PKI docs per epoch
func PKIDocs(epoch string) {
	pkiDocs.With(prometheus.Labels{"epoch": epoch}).Inc()
}

// CancelledOutgoing increments the counter for the number of cancelled outgoing requests
func CancelledOutgoing() {
	cancelledOutgoingConns.Inc()
}

// FetchedPKIDocs increments the counter for the number of fetched PKI docs per epoch
func FetchedPKIDocs(epoch string) {
	fetchedPKIDocs.With(prometheus.Labels{"epoch": epoch}).Inc()
}

// FailedFetchPKIDocs increments the counter for the number of times fetching a PKI doc failed per epoch
func FailedFetchPKIDocs(epoch string) {
	failedFetchPKIDocs.With(prometheus.Labels{"epoch": epoch}).Inc()
}

// FailedPKICacheGeneration increments the counter for the number of times generating a cached PKI doc failed
func FailedPKICacheGeneration(epoch string) {
	failedPKICacheGeneration.With(prometheus.Labels{"epoch": epoch}).Inc()
}

// InvalidPKICache increments the counter for the number of invalid cached PKI docs per epoch
func InvalidPKICache(epoch string) {
	invalidPKICache.With(prometheus.Labels{"epoch": epoch}).Inc()
}

// GaugeChannelLength sets the per-channel depth gauge. Matching the
// signature of the noprometheus stub so callers can invoke this
// unconditionally; the metric is registered above as channelUsage.
// No call site references it yet; this accessor is added so that
// future use does not require touching the instrument package.
func GaugeChannelLength(name string, length int) {
	channelUsage.With(prometheus.Labels{"channel_name": name}).Set(float64(length))
}

// RateLimitDropped increments the counter for client packets dropped by
// the gateway token-bucket admission control. Call alongside
// PacketsDropped at the rate-limit branch so the general drop counter
// stays consistent with the legacy dashboards.
func RateLimitDropped() {
	rateLimitDropped.Inc()
}

// SphinxUnwraps increments the counter for successful Sphinx unwrap
// operations. The rate of this counter is the realised Sphinx
// decryption throughput at the node.
func SphinxUnwraps() {
	sphinxUnwraps.Inc()
}

// PacketsDroppedByReason increments the per-reason drop counter for
// the supplied reason label. Use a stable, low-cardinality string
// (see the call sites for the canonical reasons). This is the
// data-driven way to identify which drop site is active without
// having to grep "Dropping packet" lines out of unstructured logs.
// Always pairs with a PacketsDropped() call at the same site so the
// aggregate legacy counter remains the sum across all reasons.
func PacketsDroppedByReason(reason string) {
	packetsDroppedByReason.With(prometheus.Labels{"reason": reason}).Inc()
}

// SelfCheckResults publishes the startup Sphinx self-check
// measurement to its prometheus gauges. opsPerSecSolo is the
// single-goroutine rate (best-case per-core); opsPerSecSaturated is
// the NumCPU-goroutines-in-parallel aggregate (realistic ceiling for
// one mix-server process when its host is busy); numCPU is the cores
// at startup. Per-machine deployments care about the solo number,
// co-tenanted deployments care about the saturated number.
func SelfCheckResults(opsPerSecSolo, opsPerSecSaturated float64, numCPU int) {
	selfCheckSphinxOpsPerSecSolo.Set(opsPerSecSolo)
	selfCheckSphinxOpsPerSecSaturated.Set(opsPerSecSaturated)
	selfCheckSphinxCores.Set(float64(numCPU))
}

// HandshakeFailure increments the failure counter for a PQ Noise
// handshake attempt. direction is "incoming" or "outgoing"; state
// is one of the wire.HandshakeState values (e.g. "message_2_receive",
// "peer_authentication") plus the synthetic "premature_close" for
// the TCP-closed-before-bytes case and "other" for anything else.
func HandshakeFailure(direction, state string) {
	handshakeFailures.With(prometheus.Labels{"direction": direction, "state": state}).Inc()
}

// HandshakeDuration observes the wall-clock time of a handshake
// attempt. direction is "incoming" or "outgoing"; result is
// "success" or "failure". Use the success quantile to gauge the
// realistic PQ-KEM cost on this host, and the failure quantile to
// confirm whether timeouts dominate the failure mode.
func HandshakeDuration(direction, result string, seconds float64) {
	handshakeDurationSeconds.With(prometheus.Labels{"direction": direction, "result": result}).Observe(seconds)
}

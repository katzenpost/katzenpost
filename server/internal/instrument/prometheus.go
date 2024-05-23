//go:build !noprometheus
// +build !noprometheus

package instrument

import (
	"fmt"
	"net/http"
	"sync"
	"time"

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
)

var monitoredChannels = struct {
	sync.Mutex
	channels map[string]chan interface{}
}{
	channels: make(map[string]chan interface{}),
}

func startChannelLenMonitor() {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for range ticker.C {
		monitoredChannels.Lock()
		for name, ch := range monitoredChannels.channels {
			channelUsage.With(prometheus.Labels{"channel_name": name}).Set(float64(len(ch)))
		}
		monitoredChannels.Unlock()
	}
}

func MonitorChannelLen(name string, ch chan interface{}) {
	monitoredChannels.Lock()
	monitoredChannels.channels[name] = ch
	monitoredChannels.Unlock()
}

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

	metricsAddress := glue.Config().Server.MetricsAddress
	if metricsAddress != "" {
		// Expose registered metrics via HTTP
		http.Handle("/metrics", promhttp.Handler())
		go http.ListenAndServe(metricsAddress, nil)
	}

	go startChannelLenMonitor()
}

// Incoming increments the counter for incoming requests
func Incoming(cmd commands.Command) {
	cmdStr := fmt.Sprintf("%T", cmd)
	incomingConns.With(prometheus.Labels{"command": cmdStr})
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
	pkiDocs.With(prometheus.Labels{"epoch": epoch})
}

// CancelledOutgoing increments the counter for the number of cancelled outgoing requests
func CancelledOutgoing() {
	cancelledOutgoingConns.Inc()
}

// FetchedPKIDocs increments the counter for the number of fetched PKI docs per epoch
func FetchedPKIDocs(epoch string) {
	fetchedPKIDocs.With(prometheus.Labels{"epoch": epoch})
}

// FailedFetchPKIDocs increments the counter for the number of times fetching a PKI doc failed per epoch
func FailedFetchPKIDocs(epoch string) {
	failedFetchPKIDocs.With(prometheus.Labels{"epoch": epoch})
}

// FailedPKICacheGeneration increments the counter for the number of times generating a cached PKI doc failed
func FailedPKICacheGeneration(epoch string) {
	failedPKICacheGeneration.With(prometheus.Labels{"epoch": epoch})
}

// InvalidPKICache increments the counter for the number of invalid cached PKI docs per epoch
func InvalidPKICache(epoch string) {
	invalidPKICache.With(prometheus.Labels{"epoch": epoch})
}

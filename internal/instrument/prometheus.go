// +build prometheus

package instrument

import (
	"fmt"
	"log"
	"net/http"

	"github.com/katzenpost/core/wire/commands"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var (
	incomingConns = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "katzenpost_incoming_total_requests",
			Help: "Number of incoming requests",
		},
		[]string{"command"},
	)
	outgoingConns = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "katzenpost_outgoing_total_connections",
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
			Name: "katzenpost_number_of_dropped_packets",
			Help: "Number of dropped packets",
		},
	)
	packetsReplayed = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "katzenpost_number_of_replayed_packets",
			Help: "Number of replayed packets"
		},
	)
	ignoredPKIDocs = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "katzenpost_total_documents_ignored",
			Help: "Number of ignored PKI Documents"
		},
	)
	kaetzchenRequests = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "katzenpost_kaetzchen_total_requests",
			Help: "Number of Kaetzchen requests",
		},
	)
	kaetzchenPacketsDropped = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "katzenpost_kaetzchen_number_of_dropped_packets",
			Help: "Number of dropped kaetzchen packets",
		},
	)
	kaetzchenRequestsDropped = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "katzenpost_kaetzchen_total_dropped_requests"
			Help: "Number of total dropped kaetzchen requests",
		},
	)
	kaetzchenRequestsFailed = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "katzenpost_kaetzchen_total_failed_requests",
			Help: "Number of total failed kaetzchen requests",
		},
	)
	mixPacketsDropped = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "katzenpost_kaetzchen_number_of_mix_packets_dropped",
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
			Name: "katzenpost_total_number_of_pki_docs_per_epoch"
			Help: "Number of pki docs in an epoch"
		},
		[]string{"epoch"},
	)
	cancelledOutgoingConns = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "katzenpost_total_cancelled_outgoing_connections",
			Help: "Number of cancelled outgoing connections",
		},
	)
	fetchedPKIDocs = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "katzenpost_total_fetched_pki_docs_per_epoch",
			Help: "Number of fetch PKI docs per epoch",
		},
		[]string{"epoch"},
	)
	failedFetchPKIDocs = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "katzenpost_total_failed_fetch_pki_docs_per_epoch",
			Help: "Number of failed PKI docs fetches per epoch"
		}
	)
	failedPKICacheGeneration = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "katzenpost_total_failed_pki_cache_generation_per_epoch",
			Help: "Number of failed PKI caches generation per epoch",
		},
		[]string{"epoch"},
	)
	invalidPKICache = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name : "katzenpost_total_invalid_pki_cache_per_epoch",
			Help : "Number of invalid PKI caches per epoch"
		}
	)

)

func Init() {
	// Register metrics
	prometheus.MustRegister(incomingConns)
	prometheus.MustRegister(outgoingConns)
	prometheus.MustRegister(ingressQueueSize)
	prometheus.MustRegister(packetsDropped)
	prometheus.MustRegister(packetsReplayed)
	prometheus.MustRegister(ignoredPKIDocs)
	prometheus.MustRegister(kaetzchenRequests)
	prometheus.MustRegister(kaetzchenPacketsDropped)
	prometheus.MustRegister(kaetzchenRequestsDropped)
	prometheus.MustRegister(kaetzchenRequestsFailed)
	prometheus.MustRegister(mixPacketsDropped)
	prometheus.MustRegister(mixQueueSize)
	prometheus.MustRegister(pkiDocs)
	prometheus.MustRegister(cancelledOutgoingConns)
	prometheus.MustRegister(fetchedPKIDocs)
	prometheus.MustRegister(failedFetchPKIDocs)
	prometheus.MustRegister(failedPKICacheGeneration)
	prometheus.MustRegister(invalidPKICache)

	// Expose registered metrics via HTTP
	http.Handle("/metrics", promhttp.Handler())
	go http.ListenAndServe(":6543", nil)
}

func Incoming(cmd commands.Command) {
	cmdStr := fmt.Sprintf("%T", cmd)
	incomingConns.With(prometheus.Labels{"command": cmdStr})
}

func Outgoing() {
	outgoingConns.Inc()

}

func IngressQueue(size uint8) {
	ingressQueueSize.Observe(float64(size))
}

func PacketsDropped() {
	packetsDropped.Inc()

func PacketsReplayed() {
	packetsReplayed.Inc()
}

func IgnoredPKIDocs() {
	ignoredPKIDocs.Inc()
}

func KaetzchenPacketsDropped() {
	kaetzchenPacketsDropped.Inc()
}

func KaetzchenRequests() {
	kaetzchenRequests.Inc()
}

func KaetzchenRequestsDropped(dropCounter uint64) {
	kaetzchenRequestsDropped.Add(dropCounter)
}

func KaetzchenRequestsFailed() {
	kaetzchenRequestsFailed.Inc()
}

func MixPacketsDropped() {
	mixPacketsDropped.Inc()
}

func MixQueueSize(size uint64) {
	mixQueueSize.Observe(float64(size))
}

func PKIDocs(epoch string) {
	pkiDocs.With(prometheus.Labels{"epoch": epoch})
}

func CancelledOutgoing() {
	cancelledOutgoingConns.Inc()
}

func FetchedPKIDocs(epoch string) {
	fetchedPKIDocs.With(prometheus.Labels{"epoch": epoch})
}

func FailedFetchPKIDocs(epoch string) {
	failedFetchPKIDocs.With(prometheus.Labels{"epoch": epoch})
}

func FailedPKICacheGeneration(epoch string) {
	failedPKICacheGeneration.With(prometheus.Labels{"epoch": epoch})
}

func InvalidPKICache(epoch string) {
	invalidPKICache.With(prometheus.Labels{"epoch": epoch})
}
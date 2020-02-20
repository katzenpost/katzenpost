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
	packetsReplayed = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "katzenpost_replayed_packets_total",
			Help: "Number of replayed packets"
		},
	)
	ignoredPKIDocs = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "katzenpost_documents_ignored_total",
			Help: "Number of ignored PKI Documents"
		},
	)
	kaetzchenRequests = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "katzenpost_kaetzchen_requests_total",
			Help: "Number of Kaetzchen requests",
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
			Name: "katzenpost_kaetzchen_dropped_requests_total"
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
			Name: "katzenpost_pki_docs_per_epoch_total"
			Help: "Number of pki docs in an epoch"
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
	failedFetchPKIDocs = prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "katzenpost_failed_fetch_pki_docs_per_epoch_total",
			Help: "Number of failed PKI docs fetches per epoch"
		}
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
			Name : "katzenpost_invalid_pki_cache_per_epoch_total",
			Help : "Number of invalid PKI caches per epoch"
		}
	)

)
// Initialize instrumentation
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
	prometheus.MustRegister(fErica proves that she is salted peer that Bob is connected to.
		Erica proves she ran the SMP correctly for each peer.
		Alice completes SMP correctly for the search term Carroll.
		Alice aggregates the proofs together to create a single proof of connection that hides the SMP which could allow Erica to identify the proof.
		￼
		1058×794 37 KB
		Who knows what
		Alice knows that she is connected by two hops to Carroll.
		Bob knows that one of his peers was trying to search for someone
		Erica knows that one of her peer was searching for someone
		In order to prevent people from seeing if a search attempt succeeded its important to create proofs for every search attempt.
		
		We also need to continue the search to a certain depth in the social tree even if we have created the proof.
		
		This might be prohibitively expensive but we can make a trade off here.
		
		Attacks
		An attacker can brute force the network looking for peers
		We can use a ZKP in order to rate limit all requests. github.com/kobigurk/semaphore, Semaphore RLN, rate limiting nullifier for spam prevention in anonymous p2p setting 1
		
		Loop attack: An attacker creates a loop of peailedPKICacheGeneration)
	prometheus.MustRegister(invalidPKICache)

	// Expose registered metrics via HTTP
	http.Handle("/metrics", promhttp.Handler())
	go http.ListenAndServe(":6543", nil)
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
	kaetzchenRequestsDropped.Add(dropCounter)
}

// KaetzchenRequestsFailed increments the counter for the number of failed kaetzchen requests
func KaetzchenRequestsFailed() {
	kaetzchenRequestsFailed.Inc()
}

// MixPacketsDropped increments the counter for the number of mix packets dropped
func MixPacketsDropped() {
	mixPacketsDropped.Inc()
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
// +build !prometheus

package instrument

import (
	"github.com/katzenpost/core/wire/commands"
)

// Init instrumentation
func Init() {}

// Incoming increments the counter for incoming requests
func Incoming(cmd commands.Command) {}

// Outgoing increments the counter for outgoing connections
func Outgoing() {}

// IngressQueue observes the size of the ingress queue
func IngressQueue(size uint8) {}

// PacketsDropped increments the counter for the number of packets dropped
func PacketsDropped() {}

// PacketsReplayed increments the counter for the number of replayed packets
func PacketsReplayed() {}

// IgnoredPKIDocs increments the counter for the number of ignored PKI docs
func IgnoredPKIDocs() {}

// KaetzchenPacketsDropped increments the counter for the number of dropped Kaetzchen requests
func KaetzchenPacketsDropped() {}

// KaetzchenRequests increments the counter for the number of kaetzchen requests
func KaetzchenRequests() {}

// KaetzchenRequestsDuration times amount of time for a kaetzchen request
func KaetzchenRequestsDuration() {}

// KaetzchenRequestsDropped increments the counter for the number of dropped kaetzchen requests
func KaetzchenRequestsDropped(dropCounter uint64) {}

// KaetzchenRequestsFailed increments the counter for the number of failed kaetzchen requests
func KaetzchenRequestsFailed() {}

// MixPacketsDropped increments the counter for the number of mix packets dropped
func MixPacketsDropped() {}

// MixQueueSize observes the size of the mix queue
func MixQueueSize(size uint64) {}

// PKIDocs increments the counter for the number of PKI docs per epoch
func PKIDocs(epoch string) {}

// CancelledOutgoing increments the counter for the number of cancelled outgoing requests
func CancelledOutgoing() {}

// FetchedPKIDocs increments the counter for the number of fetched PKI docs per epoch
func FetchedPKIDocs(epoch string) {}

// FetchedPKIDocsDuration times the time it takes to a fetch a PKI doc in an epoch
func FetchedPKIDocsDuration() {}

// FailedFetchPKIDocs increments the counter for the number of times fetching a PKI doc failed per epoch
func FailedFetchPKIDocs(epoch string) {}

// FailedPKICacheGeneration increments the counter for the number of times generating a cached PKI doc failed
func FailedPKICacheGeneration(epoch string) {}

// InvalidPKICache increments the counter for the number of invalid cached PKI docs per epoch
func InvalidPKICache(epoch string) {}

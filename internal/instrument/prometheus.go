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
			Name: "katzenpost_incoming_total_request",
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
	ingressQueueSize = prometheus.NewGauge(
		prometheus.GaugeOpts{
			Name: "katzenpost_ingress_queue_size",
			Help: "Size of the ingress queue",
		},
	)
)

func Init() {
	// Register metrics
	prometheus.MustRegister(incomingConns)
	prometheus.MustRegister(outgoingConns)
	prometheus.MustRegister(ingressQueueSize)
	prometheus.MustRegister(mixingQueueSize)

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
	ingressQueueSize.Set(float64(size))
}

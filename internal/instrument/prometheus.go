package instrument

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Init initialize instrumentation
func Init() {
	// Expose registered metrics via HTTP
	http.Handle("/metrics", promhttp.Handler())
	go http.ListenAndServe(":6543", nil)
}

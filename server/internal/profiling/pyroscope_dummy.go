//go:build !pyroscope
// +build !pyroscope

package profiling

import "gopkg.in/op/go-logging.v1"

// Start is a dummy function that does nothing.
func Start(log *logging.Logger) error {
	log.Info("Pyroscope is disabled")
	return nil
}

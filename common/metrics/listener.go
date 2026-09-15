// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

// Package metrics provides the HTTP listener shared by the
// prometheus instrumentation packages of every Katzenpost daemon.
// Only the prometheus-enabled builds of those packages import it, so
// the noprometheus and !kpclientd_metrics builds still compile out the
// dependency on prometheus/client_golang entirely.
package metrics

import (
	"fmt"
	"net"
	"net/http"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"gopkg.in/op/go-logging.v1"
)

// MustServe is Serve, but panics rather than returning the bind error.
// Every Katzenpost daemon uses this: a MetricsAddress that cannot be
// bound is an operator configuration error, and a component that came
// up anyway would leave a scrape target answering nothing. Failing
// loudly at startup is the whole point of binding synchronously.
func MustServe(address string, log *logging.Logger) {
	if err := Serve(address, log); err != nil {
		panic(err)
	}
}

// Serve exposes the registered prometheus metrics as /metrics on
// address.
//
// The socket is bound synchronously, so a bind failure (a port already
// in use, or an address that is not local to this host) is returned to
// the caller rather than lost inside a goroutine; only the accept loop
// runs in the background. Most callers want MustServe; Serve exists for
// tests and for any caller that must handle the failure itself.
//
// A nil log is permitted, and suppresses reporting of a failure that
// stops the accept loop after a successful bind.
func Serve(address string, log *logging.Logger) error {
	ln, err := net.Listen("tcp", address)
	if err != nil {
		return fmt.Errorf("prometheus metrics listener: cannot bind %q: %w", address, err)
	}

	// A dedicated mux rather than http.DefaultServeMux: the default
	// mux is process global, so anything else that registers a
	// handler on it would be served on this socket too, and a second
	// call here would panic on the duplicate /metrics registration.
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.Handler())

	go func() {
		err := http.Serve(ln, mux)
		if log != nil {
			log.Errorf("Prometheus metrics listener on %s stopped serving: %v", address, err)
		}
	}()
	return nil
}

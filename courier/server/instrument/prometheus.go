// SPDX-FileCopyrightText: Copyright (C) 2025 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package instrument

import (
	"net/http"
	"sync"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

var registerOnce sync.Once

var (
	decoysSent = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "katzenpost_courier_decoys_sent_total",
			Help: "Number of decoy messages sent to replicas",
		},
	)
	messagesSent = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "katzenpost_courier_messages_sent_total",
			Help: "Number of real messages sent to replicas",
		},
	)
	queueLength = prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: "katzenpost_courier_queue_length",
			Help: "Current queue depth per replica connection",
		},
		[]string{"replica"},
	)
	messagesReceived = prometheus.NewCounter(
		prometheus.CounterOpts{
			Name: "katzenpost_courier_messages_received_total",
			Help: "Number of messages received from mix server",
		},
	)
)

// StartPrometheusListener registers metrics and starts the HTTP listener
// if address is non-empty.
func StartPrometheusListener(address string) {
	registerOnce.Do(func() {
		prometheus.MustRegister(decoysSent)
		prometheus.MustRegister(messagesSent)
		prometheus.MustRegister(queueLength)
		prometheus.MustRegister(messagesReceived)
	})

	if address != "" {
		http.Handle("/metrics", promhttp.Handler())
		go http.ListenAndServe(address, nil)
	}
}

// DecoysSent increments the counter for decoy messages sent
func DecoysSent() {
	decoysSent.Inc()
}

// MessagesSent increments the counter for real messages sent
func MessagesSent() {
	messagesSent.Inc()
}

// QueueLength sets the queue depth gauge for a replica
func QueueLength(replica string, length int) {
	queueLength.With(prometheus.Labels{"replica": replica}).Set(float64(length))
}

// MessagesReceived increments the counter for messages received from mix server
func MessagesReceived() {
	messagesReceived.Inc()
}

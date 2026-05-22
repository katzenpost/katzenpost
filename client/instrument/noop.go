// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

//go:build !kpclientd_metrics

// Package instrument under the !kpclientd_metrics build tag exposes
// no-op stubs that match the signatures of the real instrumented build.
// This lets callers throughout the client invoke instrument.* functions
// unconditionally without paying the dependency on
// prometheus/client_golang or shipping a /metrics listener in
// production binaries. Build with -tags kpclientd_metrics to enable the
// real implementation defined in prometheus.go.
package instrument

import "time"

// StartPrometheusListener is a no-op when the build tag is unset.
func StartPrometheusListener(_ string) {}

// LambdaPFifoPop is a no-op when the build tag is unset.
func LambdaPFifoPop() {}

// LambdaPDecoy is a no-op when the build tag is unset.
func LambdaPDecoy() {}

// LambdaLDecoy is a no-op when the build tag is unset.
func LambdaLDecoy() {}

// SendQueueEnqueue is a no-op when the build tag is unset.
func SendQueueEnqueue() {}

// SendQueueDequeue is a no-op when the build tag is unset.
func SendQueueDequeue() {}

// ARQInflightSet is a no-op when the build tag is unset.
func ARQInflightSet(_ int) {}

// GatewayConnected is a no-op when the build tag is unset.
func GatewayConnected(_ bool) {}

// PKIDocFetched is a no-op when the build tag is unset.
func PKIDocFetched(_ time.Time) {}

// ARQRoundTrip is a no-op when the build tag is unset.
func ARQRoundTrip(_ time.Duration) {}

// SurbIDCreated is a no-op when the build tag is unset.
func SurbIDCreated() {}

// SurbIDGarbageCollected is a no-op when the build tag is unset.
func SurbIDGarbageCollected() {}

// SurbIDReplyMatched is a no-op when the build tag is unset.
func SurbIDReplyMatched() {}

// SurbIDDelivered is a no-op when the build tag is unset.
func SurbIDDelivered() {}

// SurbIDReplyNoMatch is a no-op when the build tag is unset.
func SurbIDReplyNoMatch() {}

// SurbIDRotated is a no-op when the build tag is unset.
func SurbIDRotated() {}

// ThinSessionsSet is a no-op when the build tag is unset.
func ThinSessionsSet(_ int) {}

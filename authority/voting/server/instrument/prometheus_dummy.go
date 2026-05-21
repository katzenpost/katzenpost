// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

//go:build noprometheus

// Package instrument under the noprometheus build tag exposes no-op
// stubs that match the signatures of the real instrumented build. This
// lets callers throughout the dirauth invoke instrument.* functions
// unconditionally without paying the dependency on
// prometheus/client_golang. Build the dirauth without -tags
// noprometheus to enable the real implementation defined in
// prometheus.go.
package instrument

import "time"

// StartPrometheusListener is a no-op when the noprometheus build tag is set.
func StartPrometheusListener(_ string) {}

// VoteReceived is a no-op when the noprometheus build tag is set.
func VoteReceived(_ string) {}

// DescriptorAccepted is a no-op when the noprometheus build tag is set.
func DescriptorAccepted(_ string) {}

// DescriptorRejected is a no-op when the noprometheus build tag is set.
func DescriptorRejected(_, _ string) {}

// ConsensusReached is a no-op when the noprometheus build tag is set.
func ConsensusReached() {}

// PeerSendAttempt is a no-op when the noprometheus build tag is set.
func PeerSendAttempt(_, _ string) {}

// VotingPhase is a no-op when the noprometheus build tag is set.
func VotingPhase(_ string) {}

// PeerConnected is a no-op when the noprometheus build tag is set.
func PeerConnected(_ string, _ bool) {}

// CurrentEpoch is a no-op when the noprometheus build tag is set.
func CurrentEpoch(_ uint64) {}

// DocumentGenerated is a no-op when the noprometheus build tag is set.
func DocumentGenerated(_ time.Duration) {}

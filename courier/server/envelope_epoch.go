// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package server

// ValidCourierEnvelopeEpochWindow is the symmetric tolerance applied
// to a CourierEnvelope's declared replica epoch. The courier accepts
// envelopes whose epoch falls within [current - window, current + window]
// where "current" is the courier's view of the current replica epoch.
//
// A window of 1 means three acceptable epochs at any moment:
// {current-1, current, current+1}. See the Pigeonhole specification
// section "Epoch tolerance for CourierEnvelope" for the reasoning.
const ValidCourierEnvelopeEpochWindow uint64 = 1

// isEnvelopeEpochAcceptable reports whether envelopeEpoch falls within
// ±ValidCourierEnvelopeEpochWindow of currentEpoch. Written to avoid
// uint64 underflow when envelopeEpoch < currentEpoch.
func isEnvelopeEpochAcceptable(envelopeEpoch, currentEpoch uint64) bool {
	if envelopeEpoch > currentEpoch {
		return envelopeEpoch-currentEpoch <= ValidCourierEnvelopeEpochWindow
	}
	return currentEpoch-envelopeEpoch <= ValidCourierEnvelopeEpochWindow
}

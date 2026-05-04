// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package replica

import (
	"fmt"

	"github.com/katzenpost/hpqc/kem/mkem"

	replicaCommon "github.com/katzenpost/katzenpost/replica/common"
)

// ValidEnvelopeEpochWindow is the symmetric tolerance the replica
// applies when decapsulating an inbound MKEM ciphertext. It MUST match
// the courier's ValidCourierEnvelopeEpochWindow, so any envelope the
// courier decided to forward has a matching private key to try here.
//
// A window of 1 means three candidate epochs at any moment:
// {current-1, current, current+1}. See the Pigeonhole specification
// section "Epoch tolerance for CourierEnvelope" for the reasoning.
const ValidEnvelopeEpochWindow uint64 = 1

// tryDecapsulateAcrossEpochWindow attempts MKEM decapsulation using
// each envelope keypair in the replica's epoch-tolerance window.
// Returns the decrypted plaintext plus the replica-epoch whose keypair
// succeeded, or a non-nil error if no available key can decapsulate
// the ciphertext.
//
// The iteration order is {current-1, current, current+1}. Missing
// keys (GetKeypair returns an error) are skipped silently — that's
// the normal state at process start (the next-epoch key is generated
// by the PKI publisher loop, not at boot). Decapsulation failures are
// remembered and surfaced as the returned error when every candidate
// has been tried.
func tryDecapsulateAcrossEpochWindow(
	keys *EnvelopeKeys,
	scheme *mkem.Scheme,
	ct *mkem.Ciphertext,
	currentEpoch uint64,
) ([]byte, *replicaCommon.EnvelopeKey, uint64, error) {
	var lastErr error
	window := int64(ValidEnvelopeEpochWindow)
	for delta := -window; delta <= window; delta++ {
		if delta < 0 && uint64(-delta) > currentEpoch {
			// uint64 underflow guard — at epoch 0 the "previous" epoch
			// doesn't exist.
			continue
		}
		epoch := uint64(int64(currentEpoch) + delta)
		keypair, err := keys.GetKeypair(epoch)
		if err != nil {
			continue
		}
		plaintext, err := scheme.Decapsulate(keypair.PrivateKey, ct)
		if err != nil {
			lastErr = err
			continue
		}
		return plaintext, keypair, epoch, nil
	}
	if lastErr == nil {
		return nil, nil, 0, fmt.Errorf(
			"no envelope keys available in tolerance window around replica epoch %d",
			currentEpoch,
		)
	}
	return nil, nil, 0, lastErr
}

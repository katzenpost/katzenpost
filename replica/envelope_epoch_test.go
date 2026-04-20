// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package replica

import (
	"os"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/kem/mkem"
	"github.com/katzenpost/hpqc/nike"
	nikeschemes "github.com/katzenpost/hpqc/nike/schemes"

	"github.com/katzenpost/katzenpost/core/log"
	replicaCommon "github.com/katzenpost/katzenpost/replica/common"
)

// envelopeKeysWithEpochs builds an EnvelopeKeys populated with freshly
// generated keypairs for the requested replica-epochs. The caller is
// responsible for the temporary data dir cleanup.
func envelopeKeysWithEpochs(t *testing.T, epochs []uint64) (*EnvelopeKeys, nike.Scheme) {
	t.Helper()
	logBackend, err := log.New("", "DEBUG", false)
	require.NoError(t, err)

	dname, err := os.MkdirTemp("", "replica.envelope-epoch")
	require.NoError(t, err)
	t.Cleanup(func() { os.RemoveAll(dname) })

	scheme := nikeschemes.ByName("CTIDH512-X25519")
	keys := &EnvelopeKeys{
		log:      logBackend.GetLogger("envelope keys"),
		datadir:  dname,
		scheme:   scheme,
		keysLock: new(sync.RWMutex),
		keys:     make(map[uint64]*replicaCommon.EnvelopeKey),
	}
	for _, e := range epochs {
		require.NoError(t, keys.Generate(e))
	}
	return keys, scheme
}

// TestValidEnvelopeEpochWindowMatchesCourier pins the invariant that
// the replica's tolerance window equals the courier's. If a reviewer
// widens one without the other, any envelope the lax side accepts
// will silently fail at the strict side.
func TestValidEnvelopeEpochWindowMatchesCourier(t *testing.T) {
	// We can't import server (import cycle) — pin the literal value,
	// and a matching pin exists in courier/server/envelope_epoch_test.go.
	require.Equal(t, uint64(1), ValidEnvelopeEpochWindow)
}

// TestTryDecapsulateAcrossEpochWindowSucceedsForCurrent is the baseline:
// a ciphertext encrypted to the current-epoch public key decapsulates.
func TestTryDecapsulateAcrossEpochWindowSucceedsForCurrent(t *testing.T) {
	const current uint64 = 100
	keys, nikeScheme := envelopeKeysWithEpochs(t, []uint64{current - 1, current, current + 1})
	mscheme := mkem.NewScheme(nikeScheme)

	kp, err := keys.GetKeypair(current)
	require.NoError(t, err)

	payload := []byte("hello-current-epoch")
	_, ct := mscheme.Encapsulate([]nike.PublicKey{kp.PublicKey}, payload)
	decapCt := &mkem.Ciphertext{
		EphemeralPublicKey: ct.EphemeralPublicKey,
		DEKCiphertexts:     []*[mkem.DEKSize]byte{ct.DEKCiphertexts[0]},
		Envelope:           ct.Envelope,
	}

	pt, decapKp, epoch, err := tryDecapsulateAcrossEpochWindow(keys, mscheme, decapCt, current)
	require.NoError(t, err)
	require.Equal(t, payload, pt)
	require.Equal(t, current, epoch, "should report which epoch's key succeeded")
	require.NotNil(t, decapKp, "returned keypair must be non-nil on success (reply encryption depends on it)")
	require.Equal(t, kp.PublicKey, decapKp.PublicKey, "returned keypair must be the one that decapped")
}

// TestTryDecapsulateAcrossEpochWindowSucceedsForPrevious covers the
// grace window immediately after a replica-epoch boundary: a client
// with slightly stale PKI encrypted to current-1, and the replica has
// just rolled into "current". The previous-epoch keypair is still in
// memory (H5's startup-load fix) so decapsulation must still succeed.
func TestTryDecapsulateAcrossEpochWindowSucceedsForPrevious(t *testing.T) {
	const current uint64 = 100
	keys, nikeScheme := envelopeKeysWithEpochs(t, []uint64{current - 1, current, current + 1})
	mscheme := mkem.NewScheme(nikeScheme)

	prevKp, err := keys.GetKeypair(current - 1)
	require.NoError(t, err)

	payload := []byte("encrypted-before-rollover")
	_, ct := mscheme.Encapsulate([]nike.PublicKey{prevKp.PublicKey}, payload)
	decapCt := &mkem.Ciphertext{
		EphemeralPublicKey: ct.EphemeralPublicKey,
		DEKCiphertexts:     []*[mkem.DEKSize]byte{ct.DEKCiphertexts[0]},
		Envelope:           ct.Envelope,
	}

	pt, decapKp, epoch, err := tryDecapsulateAcrossEpochWindow(keys, mscheme, decapCt, current)
	require.NoError(t, err)
	require.Equal(t, payload, pt)
	require.Equal(t, current-1, epoch)
	require.Equal(t, prevKp.PublicKey, decapKp.PublicKey)
}

// TestTryDecapsulateAcrossEpochWindowSucceedsForNext covers the
// opposite boundary: a client whose PKI view is slightly ahead
// encrypted to current+1 — the PKI publisher has already generated
// that keypair, so we must accept it.
func TestTryDecapsulateAcrossEpochWindowSucceedsForNext(t *testing.T) {
	const current uint64 = 100
	keys, nikeScheme := envelopeKeysWithEpochs(t, []uint64{current - 1, current, current + 1})
	mscheme := mkem.NewScheme(nikeScheme)

	nextKp, err := keys.GetKeypair(current + 1)
	require.NoError(t, err)

	payload := []byte("encrypted-ahead-of-rollover")
	_, ct := mscheme.Encapsulate([]nike.PublicKey{nextKp.PublicKey}, payload)
	decapCt := &mkem.Ciphertext{
		EphemeralPublicKey: ct.EphemeralPublicKey,
		DEKCiphertexts:     []*[mkem.DEKSize]byte{ct.DEKCiphertexts[0]},
		Envelope:           ct.Envelope,
	}

	pt, decapKp, epoch, err := tryDecapsulateAcrossEpochWindow(keys, mscheme, decapCt, current)
	require.NoError(t, err)
	require.Equal(t, payload, pt)
	require.Equal(t, current+1, epoch)
	require.Equal(t, nextKp.PublicKey, decapKp.PublicKey)
}

// TestTryDecapsulateAcrossEpochWindowRejectsOutOfWindow verifies that
// a ciphertext encrypted to a key outside the {current-1, current,
// current+1} window cannot be decapsulated even if the replica still
// holds that key in memory (e.g. during a pending prune). Tolerance
// window MUST NOT widen silently.
func TestTryDecapsulateAcrossEpochWindowRejectsOutOfWindow(t *testing.T) {
	const current uint64 = 100
	// Note: we include current-2 in the in-memory set to prove the
	// window — not key availability — is what bounds us.
	keys, nikeScheme := envelopeKeysWithEpochs(t, []uint64{current - 2, current - 1, current, current + 1})
	mscheme := mkem.NewScheme(nikeScheme)

	oldKp, err := keys.GetKeypair(current - 2)
	require.NoError(t, err)

	payload := []byte("encrypted-too-long-ago")
	_, ct := mscheme.Encapsulate([]nike.PublicKey{oldKp.PublicKey}, payload)
	decapCt := &mkem.Ciphertext{
		EphemeralPublicKey: ct.EphemeralPublicKey,
		DEKCiphertexts:     []*[mkem.DEKSize]byte{ct.DEKCiphertexts[0]},
		Envelope:           ct.Envelope,
	}

	_, _, _, err = tryDecapsulateAcrossEpochWindow(keys, mscheme, decapCt, current)
	require.Error(t, err, "ciphertext outside the tolerance window must not decapsulate")
}

// TestTryDecapsulateAcrossEpochWindowNoKeysAvailable covers the
// cold-start / fresh-install edge case: the keyring is empty. We
// expect a clean error rather than a panic.
func TestTryDecapsulateAcrossEpochWindowNoKeysAvailable(t *testing.T) {
	keys, nikeScheme := envelopeKeysWithEpochs(t, nil)
	mscheme := mkem.NewScheme(nikeScheme)

	// An empty ciphertext is fine — we never reach the decap itself.
	decapCt := &mkem.Ciphertext{
		EphemeralPublicKey: nil,
		DEKCiphertexts:     nil,
		Envelope:           nil,
	}
	_, _, _, err := tryDecapsulateAcrossEpochWindow(keys, mscheme, decapCt, 100)
	require.Error(t, err)
	require.Contains(t, err.Error(), "no envelope keys available")
}

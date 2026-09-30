// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package replica

import (
	"os"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/kem"
	"github.com/katzenpost/hpqc/kem/mrhybrid"
	kemschemes "github.com/katzenpost/hpqc/kem/schemes"

	"github.com/katzenpost/katzenpost/core/log"
	replicaCommon "github.com/katzenpost/katzenpost/replica/common"
)

// envelopeKeysWithEpochs builds an EnvelopeKeys populated with freshly
// generated keypairs for the requested replica-epochs. The caller is
// responsible for the temporary data dir cleanup.
func envelopeKeysWithEpochs(t *testing.T, epochs []uint64) (*EnvelopeKeys, kem.Scheme) {
	t.Helper()
	logBackend, err := log.New("", "DEBUG", false)
	require.NoError(t, err)

	dname, err := os.MkdirTemp("", "replica.envelope-epoch")
	require.NoError(t, err)
	t.Cleanup(func() { os.RemoveAll(dname) })

	// x25519 rather than the production mceliece348864-X25519: keygen
	// runs once per epoch here and McEliece keygen is comparatively slow.
	scheme := kemschemes.ByName("x25519")
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
	keys, kemScheme := envelopeKeysWithEpochs(t, []uint64{current - 1, current, current + 1})
	mscheme := mrhybrid.NewScheme(kemScheme)

	kp, err := keys.GetKeypair(current)
	require.NoError(t, err)

	payload := []byte("hello-current-epoch")
	_, ct, err := mscheme.Encapsulate([]kem.PublicKey{kp.PublicKey}, payload)
	require.NoError(t, err)

	_, pt, decapKp, epoch, err := tryDecapsulateAcrossEpochWindow(keys, mscheme, ct, current)
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
	keys, kemScheme := envelopeKeysWithEpochs(t, []uint64{current - 1, current, current + 1})
	mscheme := mrhybrid.NewScheme(kemScheme)

	prevKp, err := keys.GetKeypair(current - 1)
	require.NoError(t, err)

	payload := []byte("encrypted-before-rollover")
	_, ct, err := mscheme.Encapsulate([]kem.PublicKey{prevKp.PublicKey}, payload)
	require.NoError(t, err)

	_, pt, decapKp, epoch, err := tryDecapsulateAcrossEpochWindow(keys, mscheme, ct, current)
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
	keys, kemScheme := envelopeKeysWithEpochs(t, []uint64{current - 1, current, current + 1})
	mscheme := mrhybrid.NewScheme(kemScheme)

	nextKp, err := keys.GetKeypair(current + 1)
	require.NoError(t, err)

	payload := []byte("encrypted-ahead-of-rollover")
	_, ct, err := mscheme.Encapsulate([]kem.PublicKey{nextKp.PublicKey}, payload)
	require.NoError(t, err)

	_, pt, decapKp, epoch, err := tryDecapsulateAcrossEpochWindow(keys, mscheme, ct, current)
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
	keys, kemScheme := envelopeKeysWithEpochs(t, []uint64{current - 2, current - 1, current, current + 1})
	mscheme := mrhybrid.NewScheme(kemScheme)

	oldKp, err := keys.GetKeypair(current - 2)
	require.NoError(t, err)

	payload := []byte("encrypted-too-long-ago")
	_, ct, err := mscheme.Encapsulate([]kem.PublicKey{oldKp.PublicKey}, payload)
	require.NoError(t, err)

	_, _, _, _, err = tryDecapsulateAcrossEpochWindow(keys, mscheme, ct, current)
	require.Error(t, err, "ciphertext outside the tolerance window must not decapsulate")
}

// TestTryDecapsulateAcrossEpochWindowNoKeysAvailable covers the
// cold-start / fresh-install edge case: the keyring is empty. We
// expect a clean error rather than a panic.
func TestTryDecapsulateAcrossEpochWindowNoKeysAvailable(t *testing.T) {
	keys, kemScheme := envelopeKeysWithEpochs(t, nil)
	mscheme := mrhybrid.NewScheme(kemScheme)

	// An empty ciphertext is fine — we never reach the decap itself.
	decapCt := &mrhybrid.Ciphertext{
		KEMCiphertexts: nil,
		DEKCiphertexts: nil,
		Envelope:       nil,
	}
	_, _, _, _, err := tryDecapsulateAcrossEpochWindow(keys, mscheme, decapCt, 100)
	require.Error(t, err)
	require.Contains(t, err.Error(), "no envelope keys available")
}

// TestEpochWindowDeltasOrder pins the nearest-first ordering that makes
// the common case cheap. The current epoch must be tried first: a
// failed decapsulation costs a full KEM decapsulation before
// the AEAD tag rejects it, so leading with a neighbouring epoch would
// burn one on every inbound ReplicaMessage. Replica epochs are a week
// long, so "current" is very nearly always the right key.
func TestEpochWindowDeltasOrder(t *testing.T) {
	require.Equal(t, []int64{0, -1, 1}, epochWindowDeltas(1),
		"the current epoch must lead, then the neighbours outward")
	require.Equal(t, []int64{0, -1, 1, -2, 2}, epochWindowDeltas(2))
	require.Equal(t, []int64{0}, epochWindowDeltas(0))
}

// TestEpochWindowDeltasCoverWindow checks the reordering did not change
// which epochs are reachable, only the order they are tried in.
func TestEpochWindowDeltasCoverWindow(t *testing.T) {
	for _, window := range []int64{0, 1, 2, 5} {
		deltas := epochWindowDeltas(window)
		require.Len(t, deltas, int(2*window+1))

		seen := make(map[int64]bool, len(deltas))
		for _, d := range deltas {
			require.False(t, seen[d], "delta %d emitted twice for window %d", d, window)
			seen[d] = true
			require.LessOrEqual(t, d, window)
			require.GreaterOrEqual(t, d, -window)
		}
		for d := -window; d <= window; d++ {
			require.True(t, seen[d], "delta %d missing for window %d", d, window)
		}
	}
}

// TestTryDecapsulateSkipsAbsentNeighbours covers the ordering change
// against the real decapsulation path: with only the current-epoch key
// present, which is the state at process start before the PKI publisher
// has generated the next-epoch key, a current-epoch envelope must still
// decapsulate on the first attempt.
func TestTryDecapsulateSkipsAbsentNeighbours(t *testing.T) {
	currentEpoch, _, _ := replicaCommon.ReplicaNow()
	keys, kemScheme := envelopeKeysWithEpochs(t, []uint64{currentEpoch})
	scheme := mrhybrid.NewScheme(kemScheme)

	keypair, err := keys.GetKeypair(currentEpoch)
	require.NoError(t, err)

	payload := []byte("nearest-first")
	_, ct, err := scheme.Encapsulate([]kem.PublicKey{keypair.PublicKey}, payload)
	require.NoError(t, err)

	_, plaintext, gotKeypair, gotEpoch, err := tryDecapsulateAcrossEpochWindow(keys, scheme, ct, currentEpoch)
	require.NoError(t, err)
	require.Equal(t, payload, plaintext)
	require.Equal(t, currentEpoch, gotEpoch)
	gotKeypairBytes, err := keypair.PublicKey.MarshalBinary()
	require.NoError(t, err)
	wantKeypairBytes, err := gotKeypair.PublicKey.MarshalBinary()
	require.NoError(t, err)
	require.Equal(t, gotKeypairBytes, wantKeypairBytes)
}

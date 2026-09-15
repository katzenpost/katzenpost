// SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package replica

import (
	"os"
	"sync"
	"testing"

	replicaCommon "github.com/katzenpost/katzenpost/replica/common"

	"github.com/stretchr/testify/require"

	nikeschemes "github.com/katzenpost/hpqc/nike/schemes"

	"github.com/katzenpost/katzenpost/core/log"
)

func TestEnvelopeKey(t *testing.T) {
	nikeScheme := nikeschemes.ByName("CTIDH512-X25519")
	keys := replicaCommon.NewEnvelopeKey(nikeScheme)
	require.NotNil(t, keys)
}

func TestEnvelopeKeys(t *testing.T) {
	logBackend, err := log.New("", "DEBUG", false)
	require.NoError(t, err)

	dname, err := os.MkdirTemp("", "replca.testState")
	require.NoError(t, err)
	defer os.RemoveAll(dname)

	replicaScheme := nikeschemes.ByName("CTIDH512-X25519")
	keys := &EnvelopeKeys{
		log:      logBackend.GetLogger("envelope keys"),
		datadir:  dname,
		scheme:   replicaScheme,
		keysLock: new(sync.RWMutex),
		keys:     make(map[uint64]*replicaCommon.EnvelopeKey),
	}
	epoch, _, _ := replicaCommon.ReplicaNow()
	err = keys.Generate(epoch)
	require.NoError(t, err)

	ok := keys.Prune()
	require.False(t, ok)

	err = keys.Generate(epoch - 20)
	require.NoError(t, err)

	ok = keys.Prune()
	require.True(t, ok)

	keys.keysLock.Lock()
	l := len(keys.keys)
	keys.keysLock.Unlock()
	require.Equal(t, 1, l)

	keypair, err := keys.GetKeypair(epoch)
	require.NoError(t, err)
	require.NotNil(t, keypair)

	// EnsureKey for past epochs must never fabricate a new keypair:
	// any ciphertext a client sent for that epoch was encrypted to the
	// PKI-published public key we no longer (or never did) have, and a
	// freshly-generated random key cannot decrypt it.
	keypair, err = keys.EnsureKey(epoch - 20)
	require.Error(t, err)
	require.Nil(t, keypair)

	keypair, err = keys.EnsureKey(epoch - 10)
	require.Error(t, err)
	require.Nil(t, keypair)

	keypair, err = keys.GetKeypair(epoch)
	require.NoError(t, err)
	require.NotNil(t, keypair)
	keypair.PurgeKeyFiles(dname, replicaScheme, epoch)
}

// TestNewEnvelopeKeysLoadsPreviousEpochFromDisk verifies that startup
// picks up the previous replica-epoch's key file (if present on disk)
// into memory, preserving the grace-period decryption cache across a
// replica restart. Without this, a restart near an epoch boundary
// would leave ciphertexts encrypted to the prior-epoch public key
// undecryptable even though the private key is still on disk.
func TestNewEnvelopeKeysLoadsPreviousEpochFromDisk(t *testing.T) {
	logBackend, err := log.New("", "DEBUG", false)
	require.NoError(t, err)

	dname, err := os.MkdirTemp("", "replica.prevepoch-startup")
	require.NoError(t, err)
	defer os.RemoveAll(dname)

	replicaScheme := nikeschemes.ByName("CTIDH512-X25519")
	epoch, _, _ := replicaCommon.ReplicaNow()
	require.Greater(t, epoch, uint64(0), "need a non-zero epoch for this test")

	// Pre-seed disk with a key file for the previous replica epoch, as
	// if the replica had been running and then shut down.
	prevKey := replicaCommon.NewEnvelopeKey(replicaScheme)
	require.NoError(t, prevKey.WriteKeyFiles(dname, replicaScheme, epoch-1))

	// Start fresh — simulates a replica restart that initialises from the
	// pre-existing datadir for the current epoch.
	ek, err := NewEnvelopeKeys(replicaScheme, logBackend.GetLogger("envelope keys"), dname, epoch)
	require.NoError(t, err)
	defer ek.Halt()

	// The previous epoch's key must be in memory, so handleReplicaMessage
	// can still decapsulate ciphertexts encrypted to it during the
	// grace window right after a boundary.
	got, err := ek.GetKeypair(epoch - 1)
	require.NoError(t, err, "previous-epoch key file on disk must be loaded at startup")
	require.NotNil(t, got)
	require.Equal(t, prevKey.PublicKey.Bytes(), got.PublicKey.Bytes())
}

// TestEnsureKeyRefusesPastEpochs pins the invariant that EnsureKey, which
// is used by the PKI publisher to prospectively generate current and
// upcoming replica-epoch keys, never fabricates keys for past epochs.
// Fabrication is a bug because the fresh key would not match any
// previously-published envelope public key.
func TestEnsureKeyRefusesPastEpochs(t *testing.T) {
	logBackend, err := log.New("", "DEBUG", false)
	require.NoError(t, err)

	dname, err := os.MkdirTemp("", "replica.ensurekey-past")
	require.NoError(t, err)
	defer os.RemoveAll(dname)

	replicaScheme := nikeschemes.ByName("CTIDH512-X25519")
	keys := &EnvelopeKeys{
		log:      logBackend.GetLogger("envelope keys"),
		datadir:  dname,
		scheme:   replicaScheme,
		keysLock: new(sync.RWMutex),
		keys:     make(map[uint64]*replicaCommon.EnvelopeKey),
	}

	epoch, _, _ := replicaCommon.ReplicaNow()

	// Past epoch: no file on disk, not in memory — must error.
	_, err = keys.EnsureKey(epoch - 1)
	require.Error(t, err, "EnsureKey must refuse to generate a past-epoch key")

	// Past epoch: no file on disk, no resulting file on disk either.
	privFile, pubFile := (&replicaCommon.EnvelopeKey{}).KeyFileNames(dname, replicaScheme, epoch-1)
	_, statErr := os.Stat(privFile)
	require.True(t, os.IsNotExist(statErr), "no private key file must be created for a past epoch")
	_, statErr = os.Stat(pubFile)
	require.True(t, os.IsNotExist(statErr), "no public key file must be created for a past epoch")

	// Current and future epochs are legitimate: prospective publishing.
	keypair, err := keys.EnsureKey(epoch)
	require.NoError(t, err)
	require.NotNil(t, keypair)

	keypair, err = keys.EnsureKey(epoch + 1)
	require.NoError(t, err)
	require.NotNil(t, keypair)

	// An existing past-epoch key in memory (e.g., loaded from disk by a
	// future startup path, or retained by Prune) is returned unchanged —
	// EnsureKey must not replace it with a fresh random one.
	existing := replicaCommon.NewEnvelopeKey(replicaScheme)
	keys.keysLock.Lock()
	keys.keys[epoch-1] = existing
	keys.keysLock.Unlock()
	got, err := keys.EnsureKey(epoch - 1)
	require.NoError(t, err)
	require.Same(t, existing, got, "past-epoch key already in memory must be returned as-is")
}

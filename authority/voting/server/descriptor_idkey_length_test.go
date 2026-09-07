// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/hash"

	"github.com/katzenpost/katzenpost/authority/voting/server/config"
	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/wire/commands"
)

// onPostDescriptor and onPostReplicaDescriptor feed the wire-supplied descriptor
// IdentityKey into pkiSignatureScheme.UnmarshalBinaryPublicKey. A pure scheme
// (Ed25519, used here) returns an error on a wrong-length key; the hybrid scheme
// slices the input with no length guard and panics. Either way the handler must
// reject a wrong-length key with DescriptorInvalid and never panic. This test
// feeds a 4-byte identity key to both handlers and expects that rejection.
func TestPostDescriptorRejectsWrongLengthIdentityKey(t *testing.T) {
	backend, err := log.New(filepath.Join(t.TempDir(), "test.log"), "ERROR", false)
	require.NoError(t, err)

	srv := &Server{
		cfg:   &config.Config{Server: &config.Server{PKISignatureScheme: "Ed25519"}},
		state: &state{},
		log:   backend.GetLogger("descriptor-idkey"),
	}
	now, _, _ := epochtime.Now()

	// A 4-byte identity key: not the Ed25519 public-key size (32 bytes).
	shortKey := []byte{1, 2, 3, 4}
	keyHash := hash.Sum256(shortKey)

	t.Run("mix", func(t *testing.T) {
		su := &pki.SignedUpload{MixDescriptor: &pki.MixDescriptor{IdentityKey: shortKey}}
		raw, err := su.Marshal()
		require.NoError(t, err)

		var resp commands.Command
		require.NotPanics(t, func() {
			resp = srv.onPostDescriptor("peer", &commands.PostDescriptor{Epoch: now, Payload: raw}, keyHash[:])
		}, "onPostDescriptor must not panic on a wrong-length identity key")

		status, ok := resp.(*commands.PostDescriptorStatus)
		require.True(t, ok)
		require.EqualValues(t, commands.DescriptorInvalid, status.ErrorCode,
			"a mix descriptor with a wrong-length identity key must be rejected with DescriptorInvalid")
	})

	t.Run("replica", func(t *testing.T) {
		su := &pki.SignedReplicaUpload{ReplicaDescriptor: &pki.ReplicaDescriptor{IdentityKey: shortKey}}
		raw, err := su.Marshal()
		require.NoError(t, err)

		var resp commands.Command
		require.NotPanics(t, func() {
			resp = srv.onPostReplicaDescriptor("peer", &commands.PostReplicaDescriptor{Epoch: now, Payload: raw}, keyHash[:])
		}, "onPostReplicaDescriptor must not panic on a wrong-length identity key")

		status, ok := resp.(*commands.PostReplicaDescriptorStatus)
		require.True(t, ok)
		require.EqualValues(t, commands.DescriptorInvalid, status.ErrorCode,
			"a replica descriptor with a wrong-length identity key must be rejected with DescriptorInvalid")
	})
}

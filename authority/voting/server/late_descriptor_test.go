// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"testing"

	"github.com/stretchr/testify/require"

	signschemes "github.com/katzenpost/hpqc/sign/schemes"

	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/pki"
)

func TestDescriptorAfterOurVoteIsLate(t *testing.T) {
	epoch, _, _ := epochtime.Now()
	s := signschemes.ByName(testSchemeName)
	require.NotNil(t, s)
	ownPub, _, err := s.GenerateKey()
	require.NoError(t, err)

	mix := func(name string) ([]byte, *pki.MixDescriptor) {
		pub, priv, err := s.GenerateKey()
		require.NoError(t, err)
		idKey, err := pub.MarshalBinary()
		require.NoError(t, err)
		su := &pki.SignedUpload{MixDescriptor: &pki.MixDescriptor{Name: name, Epoch: epoch, IdentityKey: idKey}}
		require.NoError(t, su.Sign(priv, pub))
		raw, err := su.Marshal()
		require.NoError(t, err)
		got := new(pki.SignedUpload)
		require.NoError(t, got.Unmarshal(raw))
		return raw, got.MixDescriptor
	}
	replica := func(name string) ([]byte, *pki.ReplicaDescriptor) {
		pub, priv, err := s.GenerateKey()
		require.NoError(t, err)
		idKey, err := pub.MarshalBinary()
		require.NoError(t, err)
		su := &pki.SignedReplicaUpload{ReplicaDescriptor: &pki.ReplicaDescriptor{Name: name, Epoch: epoch, IdentityKey: idKey}}
		require.NoError(t, su.Sign(priv, pub))
		raw, err := su.Marshal()
		require.NoError(t, err)
		got := new(pki.SignedReplicaUpload)
		require.NoError(t, got.Unmarshal(raw))
		return raw, got.ReplicaDescriptor
	}

	st := newUploadState(t)
	st.s = &Server{identityPublicKey: ownPub}
	st.votes = make(map[uint64]map[[publicKeyHashSize]byte]*pki.Document)

	onTimeRaw, onTime := mix("mix-on-time")
	require.NoError(t, st.onDescriptorUpload(onTimeRaw, onTime, epoch))
	onTimeReplicaRaw, onTimeReplica := replica("replica-on-time")
	require.NoError(t, st.onReplicaDescriptorUpload(onTimeReplicaRaw, onTimeReplica, epoch))

	st.votes[epoch] = map[[publicKeyHashSize]byte]*pki.Document{st.identityPubKeyHash(): {}}

	require.NoError(t, st.onDescriptorUpload(onTimeRaw, onTime, epoch))
	require.NoError(t, st.onReplicaDescriptorUpload(onTimeReplicaRaw, onTimeReplica, epoch))

	raw, desc := mix("mix-late")
	require.ErrorIs(t, st.onDescriptorUpload(raw, desc, epoch), errLateUpload)
	require.Len(t, st.descriptors[epoch], 1)
	replicaRaw, replicaDesc := replica("replica-late")
	require.ErrorIs(t, st.onReplicaDescriptorUpload(replicaRaw, replicaDesc, epoch), errLateUpload)

	raw, desc = mix("mix-next-epoch")
	require.NoError(t, st.onDescriptorUpload(raw, desc, epoch+1))
}

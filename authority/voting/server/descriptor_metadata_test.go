// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/hash"
	signschemes "github.com/katzenpost/hpqc/sign/schemes"

	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/wire/commands"
)

const testSoftwareVersion = "katzenpost 1.0"

func TestAuthorityIgnoresMalformedMetadataUnlessAccepted(t *testing.T) {
	epoch, _, _ := epochtime.Now()
	scheme := signschemes.ByName(testSchemeName)
	require.NotNil(t, scheme)
	for _, accept := range []bool{false, true} {
		t.Run(fmt.Sprint(accept), func(t *testing.T) {
			pub, priv, err := scheme.GenerateKey()
			require.NoError(t, err)
			idKey, err := pub.MarshalBinary()
			require.NoError(t, err)
			idHash := hash.Sum256(idKey)
			up := &pki.SignedUpload{MixDescriptor: &pki.MixDescriptor{
				Name:            "mix1",
				Epoch:           epoch,
				IdentityKey:     idKey,
				LinkKey:         []byte{1},
				MixKeys:         map[uint64][]byte{epoch: {1}},
				Addresses:       map[string][]string{"tcp": {"tcp://127.0.0.1:1"}},
				SoftwareVersion: testSoftwareVersion + "\n",
			}}
			require.NoError(t, up.Sign(priv, pub))
			raw, err := up.Marshal()
			require.NoError(t, err)
			srv := softwareVersionServer(t, testSchemeName, idHash)
			srv.cfg.Server.AcceptDescriptorMetadata = accept
			resp, ok := srv.onPostDescriptor("peer", &commands.PostDescriptor{Epoch: epoch, Payload: raw}, idHash[:], []byte{1}).(*commands.PostDescriptorStatus)
			require.True(t, ok)
			want := uint8(commands.DescriptorOk)
			if accept {
				want = commands.DescriptorInvalid
			}
			require.Equal(t, want, resp.ErrorCode)
		})
	}
}

func wantMetadata(accept bool) string {
	if accept {
		return testSoftwareVersion
	}
	return ""
}

func TestAuthorityDropsMixMetadataUnlessAccepted(t *testing.T) {
	epoch, _, _ := epochtime.Now()
	scheme := signschemes.ByName(testSchemeName)
	require.NotNil(t, scheme)
	for _, accept := range []bool{false, true} {
		t.Run(fmt.Sprint(accept), func(t *testing.T) {
			pub, priv, err := scheme.GenerateKey()
			require.NoError(t, err)
			idKey, err := pub.MarshalBinary()
			require.NoError(t, err)
			idHash := hash.Sum256(idKey)
			up := &pki.SignedUpload{MixDescriptor: &pki.MixDescriptor{
				Name:            "mix1",
				Epoch:           epoch,
				IdentityKey:     idKey,
				LinkKey:         []byte{1},
				MixKeys:         map[uint64][]byte{epoch: {1}},
				Addresses:       map[string][]string{"tcp": {"tcp://127.0.0.1:1"}},
				SoftwareVersion: testSoftwareVersion,
			}}
			require.NoError(t, up.Sign(priv, pub))
			raw, err := up.Marshal()
			require.NoError(t, err)
			srv := softwareVersionServer(t, testSchemeName, idHash)
			srv.cfg.Server.AcceptDescriptorMetadata = accept
			srv.state.s = srv
			resp, ok := srv.onPostDescriptor("peer", &commands.PostDescriptor{Epoch: epoch, Payload: raw}, idHash[:], []byte{1}).(*commands.PostDescriptorStatus)
			require.True(t, ok)
			require.Equal(t, uint8(commands.DescriptorOk), resp.ErrorCode)
			version := wantMetadata(accept)
			stored := srv.state.descriptors[epoch][idHash]
			require.Equal(t, version, stored.SoftwareVersion)
			restored, err := srv.state.restoredMixDescriptor(raw)
			require.NoError(t, err)
			require.Equal(t, version, restored.SoftwareVersion)
		})
	}
}

func TestAuthorityDropsReplicaMetadataUnlessAccepted(t *testing.T) {
	epoch, _, _ := epochtime.Now()
	scheme := signschemes.ByName(testSchemeName)
	require.NotNil(t, scheme)
	for _, accept := range []bool{false, true} {
		t.Run(fmt.Sprint(accept), func(t *testing.T) {
			pub, priv, err := scheme.GenerateKey()
			require.NoError(t, err)
			idKey, err := pub.MarshalBinary()
			require.NoError(t, err)
			idHash := hash.Sum256(idKey)
			up := &pki.SignedReplicaUpload{ReplicaDescriptor: &pki.ReplicaDescriptor{
				Name:            "replica1",
				ReplicaID:       1,
				Epoch:           epoch,
				IdentityKey:     idKey,
				LinkKey:         []byte{1},
				EnvelopeKeys:    map[uint64][]byte{1: {1}},
				Addresses:       map[string][]string{"tcp": {"tcp://127.0.0.1:1"}},
				SoftwareVersion: testSoftwareVersion,
			}}
			require.NoError(t, up.Sign(priv, pub))
			raw, err := up.Marshal()
			require.NoError(t, err)
			srv := softwareVersionServer(t, testSchemeName, idHash)
			srv.cfg.Server.AcceptDescriptorMetadata = accept
			srv.state.s = srv
			resp, ok := srv.onPostReplicaDescriptor("peer", &commands.PostReplicaDescriptor{Epoch: epoch, Payload: raw}, idHash[:], []byte{1}).(*commands.PostReplicaDescriptorStatus)
			require.True(t, ok)
			require.Equal(t, uint8(commands.DescriptorOk), resp.ErrorCode)
			version := wantMetadata(accept)
			stored := srv.state.replicaDescriptors[epoch][idHash]
			require.Equal(t, version, stored.SoftwareVersion)
			restored, err := srv.state.restoredReplicaDescriptor(raw)
			require.NoError(t, err)
			require.Equal(t, version, restored.SoftwareVersion)
		})
	}
}

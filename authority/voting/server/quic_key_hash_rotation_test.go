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

func TestUploadTwoQUICKeyHashes(t *testing.T) {
	epoch, _, _ := epochtime.Now()
	cases := []struct {
		n    int
		want uint8
	}{
		{64, commands.DescriptorOk},
		{48, commands.DescriptorInvalid},
		{65, commands.DescriptorInvalid},
		{96, commands.DescriptorInvalid},
	}
	for _, scheme := range []string{"Ed25519", "Ed25519 Sphincs+"} {
		s := signschemes.ByName(scheme)
		require.NotNil(t, s)
		for _, c := range cases {
			t.Run(fmt.Sprintf("%s/%d", scheme, c.n), func(t *testing.T) {
				pub, priv, err := s.GenerateKey()
				require.NoError(t, err)
				idKey, err := pub.MarshalBinary()
				require.NoError(t, err)
				idHash := hash.Sum256(idKey)
				addrs := map[string][]string{"tcp": {"tcp://127.0.0.1:1"}}
				h := make([]byte, c.n)

				mix := &pki.SignedUpload{MixDescriptor: &pki.MixDescriptor{
					Name:        "mix1",
					Epoch:       epoch,
					IdentityKey: idKey,
					LinkKey:     []byte{1},
					MixKeys:     map[uint64][]byte{epoch: {1}},
					Addresses:   addrs,
					QUICKeyHash: h,
				}}
				require.NoError(t, mix.Sign(priv, pub))
				raw, err := mix.Marshal()
				require.NoError(t, err)
				srv := quicKeyHashServer(t, scheme, idHash)
				resp, ok := srv.onPostDescriptor("peer", &commands.PostDescriptor{Epoch: epoch, Payload: raw}, idHash[:]).(*commands.PostDescriptorStatus)
				require.True(t, ok)
				require.Equal(t, c.want, resp.ErrorCode)

				replica := &pki.SignedReplicaUpload{ReplicaDescriptor: &pki.ReplicaDescriptor{
					Name:         "replica1",
					ReplicaID:    1,
					Epoch:        epoch,
					IdentityKey:  idKey,
					LinkKey:      []byte{1},
					EnvelopeKeys: map[uint64][]byte{1: {1}},
					Addresses:    addrs,
					QUICKeyHash:  h,
				}}
				require.NoError(t, replica.Sign(priv, pub))
				raw, err = replica.Marshal()
				require.NoError(t, err)
				srv = quicKeyHashServer(t, scheme, idHash)
				rresp, ok := srv.onPostReplicaDescriptor("peer", &commands.PostReplicaDescriptor{Epoch: epoch, Payload: raw}, idHash[:]).(*commands.PostReplicaDescriptorStatus)
				require.True(t, ok)
				require.Equal(t, c.want, rresp.ErrorCode)
			})
		}
	}
}

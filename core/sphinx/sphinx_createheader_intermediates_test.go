// SPDX-License-Identifier: AGPL-3.0-only

package sphinx

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/katzenpost/hpqc/nike"
	nikeSchemes "github.com/katzenpost/hpqc/nike/schemes"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/stretchr/testify/require"
)

type intermediateKeyRecorder struct {
	nike.Scheme
	secretPublicKeys  []nike.PublicKey
	blindedPublicKeys []nike.PublicKey
}

func (s *intermediateKeyRecorder) NewEmptyPublicKey() nike.PublicKey {
	pubkey := s.Scheme.NewEmptyPublicKey()
	s.secretPublicKeys = append(s.secretPublicKeys, pubkey)
	return pubkey
}

func (s *intermediateKeyRecorder) Blind(groupMember nike.PublicKey, blindingFactor nike.PrivateKey) nike.PublicKey {
	blinded := s.Scheme.Blind(groupMember, blindingFactor)
	if blinded != nil {
		s.blindedPublicKeys = append(s.blindedPublicKeys, blinded)
	}
	return blinded
}

func requireIntermediateKeysReset(t *testing.T, keys []nike.PublicKey) {
	for i, key := range keys {
		b := key.Bytes()
		require.NotEmptyf(t, b, "intermediate key %d", i)
		require.Truef(t, bytes.Equal(b, make([]byte, len(b))), "intermediate key %d not reset", i)
	}
}

func TestCreateHeaderResetsIntermediateKeys(t *testing.T) {
	const nrHops = 5
	scheme := nikeSchemes.ByName("x25519")
	g := geo.GeometryFromUserForwardPayloadLength(scheme, 200, false, nrHops)
	recorder := &intermediateKeyRecorder{Scheme: scheme}
	buildSphinx := &Sphinx{nike: recorder, geometry: g}
	_, path := newNikePathVector(require.New(t), scheme, nrHops, false)

	_, err := buildSphinx.NewPacket(rand.Reader, path, make([]byte, 200))
	require.NoError(t, err)

	intermediates := nrHops * (nrHops - 1) / 2
	require.Len(t, recorder.secretPublicKeys, intermediates)
	require.Len(t, recorder.blindedPublicKeys, intermediates)
	requireIntermediateKeysReset(t, recorder.secretPublicKeys)
	requireIntermediateKeysReset(t, recorder.blindedPublicKeys)
}

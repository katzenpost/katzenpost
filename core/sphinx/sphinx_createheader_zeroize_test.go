// SPDX-License-Identifier: AGPL-3.0-only

package sphinx

import (
	"crypto/rand"
	"testing"

	"github.com/katzenpost/hpqc/nike"
	nikeSchemes "github.com/katzenpost/hpqc/nike/schemes"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/stretchr/testify/require"
)

type captureHeaderNike struct {
	nike.Scheme
	derived      [][]byte
	blindedBytes [][]byte
}

func (s *captureHeaderNike) DeriveSecret(priv nike.PrivateKey, pub nike.PublicKey) []byte {
	ss := s.Scheme.DeriveSecret(priv, pub)
	s.derived = append(s.derived, ss)
	return ss
}

func (s *captureHeaderNike) Blind(groupMember nike.PublicKey, blindingFactor nike.PrivateKey) nike.PublicKey {
	blinded := s.Scheme.Blind(groupMember, blindingFactor)
	if blinded == nil {
		return nil
	}
	return &captureBlindedPubKey{PublicKey: blinded, capture: s}
}

type captureBlindedPubKey struct {
	nike.PublicKey
	capture *captureHeaderNike
}

func (p *captureBlindedPubKey) Bytes() []byte {
	b := p.PublicKey.Bytes()
	p.capture.blindedBytes = append(p.capture.blindedBytes, b)
	return b
}

func TestCreateHeaderZeroizesAllHopSecrets(t *testing.T) {
	require := require.New(t)
	scheme := nikeSchemes.ByName("x25519")
	g := geo.GeometryFromUserForwardPayloadLength(scheme, 200, false, 3)
	wrapped := &captureHeaderNike{Scheme: scheme}
	buildSphinx := &Sphinx{nike: wrapped, geometry: g}
	_, path := newNikePathVector(require, scheme, 3, false)
	_, err := buildSphinx.NewPacket(rand.Reader, path, make([]byte, 200))
	require.NoError(err)

	require.GreaterOrEqual(len(wrapped.derived), 3)
	for i, b := range wrapped.derived {
		require.Truef(isAllZero(b), "derived secret %d not zero", i)
	}
	require.GreaterOrEqual(len(wrapped.blindedBytes), 1)
	for i, b := range wrapped.blindedBytes {
		require.Truef(isAllZero(b), "blinded secret %d not zero", i)
	}
}

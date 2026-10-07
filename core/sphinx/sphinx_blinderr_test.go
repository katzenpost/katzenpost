// SPDX-License-Identifier: AGPL-3.0-only

package sphinx

import (
	"crypto/rand"
	"errors"
	"testing"

	"github.com/katzenpost/hpqc/nike"
	nikeSchemes "github.com/katzenpost/hpqc/nike/schemes"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/stretchr/testify/require"
)

type blindErrPublicKey struct {
	nike.PublicKey
}

func (p *blindErrPublicKey) Blind(blindingFactor nike.PrivateKey) error {
	return errors.New("sphinx_blinderr_test: forced blind error")
}

type blindErrNike struct {
	nike.Scheme
}

func (s *blindErrNike) UnmarshalBinaryPublicKey(b []byte) (nike.PublicKey, error) {
	real, err := s.Scheme.UnmarshalBinaryPublicKey(b)
	if err != nil {
		return nil, err
	}
	return &blindErrPublicKey{PublicKey: real}, nil
}

func (s *blindErrNike) DeriveSecret(priv nike.PrivateKey, pub nike.PublicKey) []byte {
	if w, ok := pub.(*blindErrPublicKey); ok {
		pub = w.PublicKey
	}
	return s.Scheme.DeriveSecret(priv, pub)
}

func TestUnwrapNikeBlindErrorReturnsError(t *testing.T) {
	require := require.New(t)
	scheme := nikeSchemes.ByName("x25519")
	g := geo.GeometryFromUserForwardPayloadLength(scheme, 200, false, 2)
	buildSphinx := NewSphinx(g)
	nodes, path := newNikePathVector(require, scheme, 2, false)
	pkt, err := buildSphinx.NewPacket(rand.Reader, path, make([]byte, 200))
	require.NoError(err)

	unwrapSphinx := &Sphinx{nike: &blindErrNike{Scheme: scheme}, geometry: g}

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Unwrap panicked instead of returning an error: %v", r)
		}
	}()
	_, _, _, err = unwrapSphinx.Unwrap(nodes[0].privateKey, pkt)
	require.Error(err)
}

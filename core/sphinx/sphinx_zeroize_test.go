// SPDX-License-Identifier: AGPL-3.0-only

package sphinx

import (
	"crypto/rand"
	"testing"

	"github.com/katzenpost/hpqc/kem"
	kemSchemes "github.com/katzenpost/hpqc/kem/schemes"
	"github.com/katzenpost/hpqc/nike"
	nikeSchemes "github.com/katzenpost/hpqc/nike/schemes"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/stretchr/testify/require"
)

type captureNike struct {
	nike.Scheme
	secrets [][]byte
}

func (s *captureNike) DeriveSecret(priv nike.PrivateKey, pub nike.PublicKey) []byte {
	ss := s.Scheme.DeriveSecret(priv, pub)
	s.secrets = append(s.secrets, ss)
	return ss
}

func isAllZero(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

func TestUnwrapNikeZeroizesSharedSecret(t *testing.T) {
	require := require.New(t)
	scheme := nikeSchemes.ByName("x25519")
	g := geo.GeometryFromUserForwardPayloadLength(scheme, 200, false, 2)
	buildSphinx := NewSphinx(g)
	nodes, path := newNikePathVector(require, scheme, 2, false)
	pkt, err := buildSphinx.NewPacket(rand.Reader, path, make([]byte, 200))
	require.NoError(err)

	wrapped := &captureNike{Scheme: scheme}
	unwrapSphinx := &Sphinx{nike: wrapped, geometry: g}
	_, _, _, err = unwrapSphinx.Unwrap(nodes[0].privateKey, pkt)
	require.NoError(err)
	require.Len(wrapped.secrets, 1)
	require.True(isAllZero(wrapped.secrets[0]))
}

func TestUnwrapNikeZeroizesSharedSecretOnMACError(t *testing.T) {
	require := require.New(t)
	scheme := nikeSchemes.ByName("x25519")
	g := geo.GeometryFromUserForwardPayloadLength(scheme, 200, false, 2)
	buildSphinx := NewSphinx(g)
	nodes, path := newNikePathVector(require, scheme, 2, false)
	pkt, err := buildSphinx.NewPacket(rand.Reader, path, make([]byte, 200))
	require.NoError(err)

	macOff := 2 + scheme.PublicKeySize() + g.RoutingInfoLength
	pkt[macOff] ^= 0xff

	wrapped := &captureNike{Scheme: scheme}
	unwrapSphinx := &Sphinx{nike: wrapped, geometry: g}
	_, _, _, err = unwrapSphinx.Unwrap(nodes[0].privateKey, pkt)
	require.Error(err)
	require.Len(wrapped.secrets, 1)
	require.True(isAllZero(wrapped.secrets[0]))
}

type captureKem struct {
	kem.Scheme
	secrets [][]byte
}

func (s *captureKem) Decapsulate(sk kem.PrivateKey, ct []byte) ([]byte, error) {
	real := sk
	if w, ok := sk.(*kemKeyWrap); ok {
		real = w.PrivateKey
	}
	ss, err := s.Scheme.Decapsulate(real, ct)
	if err == nil {
		s.secrets = append(s.secrets, ss)
	}
	return ss, err
}

type kemKeyWrap struct {
	kem.PrivateKey
	scheme kem.Scheme
}

func (w *kemKeyWrap) Scheme() kem.Scheme {
	return w.scheme
}

func TestUnwrapKemZeroizesSharedSecret(t *testing.T) {
	require := require.New(t)
	scheme := kemSchemes.ByName("x25519")
	g := geo.KEMGeometryFromUserForwardPayloadLength(scheme, 200, false, 2)
	buildSphinx := NewSphinx(g)
	nodes, path := newKEMPathVector(require, scheme, 2, false)
	pkt, err := buildSphinx.NewPacket(rand.Reader, path, make([]byte, 200))
	require.NoError(err)

	wrapped := &captureKem{Scheme: scheme}
	wrappedKey := &kemKeyWrap{PrivateKey: nodes[0].privateKey, scheme: wrapped}
	unwrapSphinx := &Sphinx{kem: wrapped, geometry: g}
	_, _, _, err = unwrapSphinx.Unwrap(wrappedKey, pkt)
	require.NoError(err)
	require.Len(wrapped.secrets, 1)
	require.True(isAllZero(wrapped.secrets[0]))
}

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

type blindErrPublicKeyHeader struct {
	nike.PublicKey
}

func (p *blindErrPublicKeyHeader) Blind(blindingFactor nike.PrivateKey) error {
	return errors.New("sphinx_createheader_blinderr_test: forced blind error")
}

type blindErrGenNike struct {
	nike.Scheme
}

func (s *blindErrGenNike) GenerateKeyPair() (nike.PublicKey, nike.PrivateKey, error) {
	pub, priv, err := s.Scheme.GenerateKeyPair()
	if err != nil {
		return nil, nil, err
	}
	return &blindErrPublicKeyHeader{PublicKey: pub}, priv, nil
}

func TestCreateHeaderBlindErrorReturnsError(t *testing.T) {
	require := require.New(t)
	scheme := nikeSchemes.ByName("x25519")
	g := geo.GeometryFromUserForwardPayloadLength(scheme, 200, false, 2)
	buildSphinx := &Sphinx{nike: &blindErrGenNike{Scheme: scheme}, geometry: g}
	_, path := newNikePathVector(require, scheme, 2, false)

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("NewPacket panicked instead of returning an error: %v", r)
		}
	}()
	_, err := buildSphinx.NewPacket(rand.Reader, path, make([]byte, 200))
	require.Error(err)
}

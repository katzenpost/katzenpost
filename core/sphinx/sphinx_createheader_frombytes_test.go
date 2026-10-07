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

type fromBytesErrPublicKey struct {
	nike.PublicKey
}

func (p *fromBytesErrPublicKey) FromBytes(data []byte) error {
	return errors.New("sphinx_createheader_frombytes_test: forced FromBytes error")
}

type fromBytesErrNike struct {
	nike.Scheme
}

func (s *fromBytesErrNike) NewEmptyPublicKey() nike.PublicKey {
	return &fromBytesErrPublicKey{PublicKey: s.Scheme.NewEmptyPublicKey()}
}

func TestCreateHeaderFromBytesErrorReturnsError(t *testing.T) {
	require := require.New(t)
	scheme := nikeSchemes.ByName("x25519")
	g := geo.GeometryFromUserForwardPayloadLength(scheme, 200, false, 2)
	buildSphinx := &Sphinx{nike: &fromBytesErrNike{Scheme: scheme}, geometry: g}
	_, path := newNikePathVector(require, scheme, 2, false)

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("NewPacket panicked instead of returning an error: %v", r)
		}
	}()
	_, err := buildSphinx.NewPacket(rand.Reader, path, make([]byte, 200))
	require.Error(err)
}

// sphinx_test.go - Sphinx Packet Format tests.
// Copyright (C) 2017  Yawning Angel.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package sphinx

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	ecdh "github.com/katzenpost/hpqc/nike/x25519"

	"github.com/katzenpost/katzenpost/core/sphinx/geo"
)

func TestEcdhSphinxGeometry(t *testing.T) {
	t.Parallel()
	require := require.New(t)

	withSURB := false
	g := geo.GeometryFromUserForwardPayloadLength(ecdh.Scheme(rand.Reader), 512, withSURB, 5)
	t.Logf("NIKE Sphinx X25519 5 hops: HeaderLength = %d", g.HeaderLength)
	g = geo.GeometryFromUserForwardPayloadLength(ecdh.Scheme(rand.Reader), 512, withSURB, 10)
	t.Logf("NIKE Sphinx X25519 10 hops: HeaderLength = %d", g.HeaderLength)

	mynike := ecdh.Scheme(rand.Reader)
	withSURB = true
	payloadLen := 50000
	g = geo.GeometryFromUserForwardPayloadLength(mynike, payloadLen, withSURB, 5)

	err := g.Validate()
	require.NoError(err)

	sphinx := NewSphinx(g)
	nrHops := 5
	_, path := newNikePathVector(require, mynike, nrHops, true)
	payload := make([]byte, g.ForwardPayloadLength)
	pkt, err := sphinx.NewPacket(rand.Reader, path, payload)
	require.NoError(err)

	t.Logf("packet length %d", len(pkt))
	t.Logf("geometry packet length %d", g.PacketLength)
	require.Equal(len(pkt), g.PacketLength)
}

func TestEcdhForwardSphinx(t *testing.T) {
	t.Parallel()
	const testPayload = "It is the stillest words that bring on the storm.  Thoughts that come on doves’ feet guide the world."

	mynike := ecdh.Scheme(rand.Reader)
	nrHops := 20
	g := geo.GeometryFromUserForwardPayloadLength(mynike, len(testPayload), false, nrHops)
	sphinx := NewSphinx(g)
	testForwardSphinx(t, mynike, sphinx, []byte(testPayload))
}

func TestEcdhSURB(t *testing.T) {
	t.Parallel()
	const testPayload = "The smallest minority on earth is the individual.  Those who deny individual rights cannot claim to be defenders of minorities."

	mynike := ecdh.Scheme(rand.Reader)
	nrHops := 20
	g := geo.GeometryFromUserForwardPayloadLength(mynike, len(testPayload), false, nrHops)
	sphinx := NewSphinx(g)
	testSURB(t, mynike, sphinx, []byte(testPayload))
}

func TestSphinxProductionSimili(t *testing.T) {
	nrHops := 5
	mynike := ecdh.Scheme(rand.Reader)

	r := require.New(t)
	_, fwdPath := newNikePathVector(r, mynike, nrHops, true)
	_, revPath := newNikePathVector(r, mynike, nrHops, true)

	g := geo.GeometryFromUserForwardPayloadLength(mynike, 2000, true, nrHops)

	s, err := FromGeometry(g)
	require.NoError(t, err)

	zeroBytes := make([]byte, g.UserForwardPayloadLength)
	payload := make([]byte, 2, g.ForwardPayloadLength)
	payload[0] = 1 // Packet has a SURB.

	surb, _, err := s.NewSURB(rand.Reader, revPath)
	require.NoError(t, err)

	payload = append(payload, surb...)
	payload = append(payload, zeroBytes...)

	require.True(t, len(payload) == g.ForwardPayloadLength)

	pkt, err := s.NewPacket(rand.Reader, fwdPath, payload)
	require.NoError(t, err)

	require.True(t, len(pkt) == g.PacketLength)
}

func TestSphinxOneHop(t *testing.T) {
	nrHops := 1
	mynike := ecdh.Scheme(rand.Reader)

	r := require.New(t)
	_, fwdPath := newNikePathVector(r, mynike, nrHops, true)
	_, revPath := newNikePathVector(r, mynike, nrHops, true)

	g := geo.GeometryFromUserForwardPayloadLength(mynike, 2000, true, nrHops)

	s, err := FromGeometry(g)
	require.NoError(t, err)

	zeroBytes := make([]byte, g.UserForwardPayloadLength)
	payload := make([]byte, 2, g.ForwardPayloadLength)
	payload[0] = 1 // Packet has a SURB.

	surb, _, err := s.NewSURB(rand.Reader, revPath)
	require.NoError(t, err)

	payload = append(payload, surb...)
	payload = append(payload, zeroBytes...)

	require.True(t, len(payload) == g.ForwardPayloadLength)

	pkt, err := s.NewPacket(rand.Reader, fwdPath, payload)
	require.NoError(t, err)

	require.True(t, len(pkt) == g.PacketLength)
}

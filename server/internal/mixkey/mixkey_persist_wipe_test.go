// SPDX-License-Identifier: AGPL-3.0-only

package mixkey

import (
	"bytes"
	"crypto/rand"
	"testing"

	"github.com/katzenpost/hpqc/kem/sntrup"
	"github.com/katzenpost/hpqc/nike"
	"github.com/katzenpost/hpqc/nike/x25519"
	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/sphinx/geo"
)

type bytesCapturingPrivateKey struct {
	nike.PrivateKey
	handedOut [][]byte
}

func (p *bytesCapturingPrivateKey) Bytes() []byte {
	b := p.PrivateKey.Bytes()
	p.handedOut = append(p.handedOut, b)
	return b
}

func TestPersistWipesMarshalledNikeKey(t *testing.T) {
	g := geo.GeometryFromUserForwardPayloadLength(x25519.Scheme(rand.Reader), 2000, true, 5)
	k, err := New(testEpoch+7, g)
	require.NoError(t, err)
	defer k.Deref()

	live := k.nikeKeypair
	want := live.Bytes()
	capture := &bytesCapturingPrivateKey{PrivateKey: live}
	k.nikeKeypair = capture

	require.NoError(t, k.Persist(t.TempDir()))

	require.Len(t, capture.handedOut, 1)
	require.Equal(t, make([]byte, len(want)), capture.handedOut[0], "marshalled private key left in memory after Persist")
	require.Equal(t, want, live.Bytes(), "Persist changed the live key")
}

func TestPersistKeepsLiveKemKey(t *testing.T) {
	g := geo.KEMGeometryFromUserForwardPayloadLength(sntrup.Scheme(), 2000, true, 5)
	k, err := New(testEpoch+8, g)
	require.NoError(t, err)
	defer k.Deref()

	want, err := k.kemKeypair.MarshalBinary()
	require.NoError(t, err)
	want = bytes.Clone(want)

	dir := t.TempDir()
	require.NoError(t, k.Persist(dir))

	got, err := k.kemKeypair.MarshalBinary()
	require.NoError(t, err)
	require.Equal(t, want, got, "Persist changed the live key")

	loaded, found, err := Load(testEpoch+8, g, dir)
	require.NoError(t, err)
	require.True(t, found)
	defer loaded.Deref()
	require.Equal(t, k.PublicBytes(), loaded.PublicBytes())
}

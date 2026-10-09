// SPDX-License-Identifier: AGPL-3.0-only

package mixkey

import (
	"bytes"
	"crypto/rand"
	"io"
	"testing"

	"github.com/katzenpost/hpqc/kem"
	"github.com/katzenpost/hpqc/kem/mlkem768"
	"github.com/katzenpost/hpqc/kem/sntrup"
	"github.com/katzenpost/hpqc/kem/xwing"
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

type marshalCapturingKemKey struct {
	kem.PrivateKey
	handedOut [][]byte
}

func (p *marshalCapturingKemKey) MarshalBinary() ([]byte, error) {
	b, err := p.PrivateKey.MarshalBinary()
	p.handedOut = append(p.handedOut, b)
	return b, err
}

func requireZeroed(t *testing.T, b []byte, msgAndArgs ...interface{}) {
	t.Helper()
	require.True(t, bytes.Equal(make([]byte, len(b)), b), msgAndArgs...)
}

type sliceCapturingWriter struct {
	w       io.Writer
	written *[][]byte
}

func (c *sliceCapturingWriter) Write(p []byte) (int, error) {
	*c.written = append(*c.written, p)
	return c.w.Write(p)
}

func captureKeyFile(t *testing.T) *[][]byte {
	var written [][]byte
	old := writeKeyFile
	writeKeyFile = func(path string, write func(io.Writer) error) error {
		return old(path, func(w io.Writer) error {
			return write(&sliceCapturingWriter{w: w, written: &written})
		})
	}
	t.Cleanup(func() { writeKeyFile = old })
	return &written
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

	require.NotEmpty(t, capture.handedOut)
	for _, b := range capture.handedOut {
		requireZeroed(t, b, "marshalled private key left in memory after Persist")
	}
	require.Equal(t, want, live.Bytes(), "Persist changed the live key")
}

func TestPersistWipesMarshalledKemKey(t *testing.T) {
	g := geo.KEMGeometryFromUserForwardPayloadLength(mlkem768.Scheme(), 2000, true, 5)
	k, err := New(testEpoch+9, g)
	require.NoError(t, err)
	defer k.Deref()

	live := k.kemKeypair
	capture := &marshalCapturingKemKey{PrivateKey: live}
	k.kemKeypair = capture

	dir := t.TempDir()
	require.NoError(t, k.Persist(dir))

	require.NotEmpty(t, capture.handedOut)
	for _, b := range capture.handedOut {
		requireZeroed(t, b, "marshalled KEM private key left in memory after Persist")
	}
	requireLiveKemKeyWorks(t, g.KEMName, live)

	loaded, found, err := Load(testEpoch+9, g, dir)
	require.NoError(t, err)
	require.True(t, found)
	defer loaded.Deref()
	requireLiveKemKeyWorks(t, g.KEMName, loaded.kemKeypair)
}

func TestPersistWipesKeyFileBuffer(t *testing.T) {
	for _, g := range []*geo.Geometry{
		geo.GeometryFromUserForwardPayloadLength(x25519.Scheme(rand.Reader), 2000, true, 5),
		geo.KEMGeometryFromUserForwardPayloadLength(mlkem768.Scheme(), 2000, true, 5),
		geo.KEMGeometryFromUserForwardPayloadLength(sntrup.Scheme(), 2000, true, 5),
	} {
		k, err := New(testEpoch+10, g)
		require.NoError(t, err)
		written := captureKeyFile(t)

		require.NoError(t, k.Persist(t.TempDir()))

		require.NotEmpty(t, *written)
		blob := (*written)[0]
		requireZeroed(t, blob, "key file buffer for %s left in memory after Persist", g.KEMName+g.NIKEName)
		k.Deref()
	}
}

func requireLiveKemKeyWorks(t *testing.T, name string, priv kem.PrivateKey) {
	t.Helper()
	s := priv.Scheme()
	require.Equal(t, name, s.Name())
	ct, ss, err := s.Encapsulate(priv.Public())
	require.NoError(t, err)
	got, err := s.Decapsulate(priv, ct)
	require.NoError(t, err)
	require.Equal(t, ss, got, "live KEM key no longer decapsulates after Persist")
}

func TestPersistKeepsLiveKemKey(t *testing.T) {
	for i, s := range []kem.Scheme{sntrup.Scheme(), xwing.Scheme()} {
		epoch := uint64(testEpoch + 8 + 100*i)
		g := geo.KEMGeometryFromUserForwardPayloadLength(s, 2000, true, 5)
		k, err := New(epoch, g)
		require.NoError(t, err)

		want, err := k.kemKeypair.MarshalBinary()
		require.NoError(t, err)
		want = bytes.Clone(want)

		dir := t.TempDir()
		require.NoError(t, k.Persist(dir))

		got, err := k.kemKeypair.MarshalBinary()
		require.NoError(t, err)
		require.Equal(t, want, got, "Persist changed the live key")
		requireLiveKemKeyWorks(t, s.Name(), k.kemKeypair)

		loaded, found, err := Load(epoch, g, dir)
		require.NoError(t, err)
		require.True(t, found)
		require.Equal(t, k.PublicBytes(), loaded.PublicBytes())
		requireLiveKemKeyWorks(t, s.Name(), loaded.kemKeypair)
		loaded.Deref()
		k.Deref()
	}
}

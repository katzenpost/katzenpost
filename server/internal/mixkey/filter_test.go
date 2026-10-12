// SPDX-License-Identifier: AGPL-3.0-only

package mixkey

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/yawning/bloom"
)

func TestReplayFilterMatchesBloom(t *testing.T) {
	var key [16]byte
	_, err := rand.Read(key[:])
	require.NoError(t, err)

	want, err := bloom.New(bytes.NewReader(key[:]), 12, 0.001)
	require.NoError(t, err)
	got, err := newReplayFilter(bytes.NewReader(key[:]), 12, 0.001)
	require.NoError(t, err)
	require.Equal(t, want.MaxEntries(), got.MaxEntries())

	for i := 0; i < 4*want.MaxEntries(); i++ {
		var tag [TagLength]byte
		binary.BigEndian.PutUint64(tag[:], uint64(i%(2*want.MaxEntries())))
		require.Equal(t, want.TestAndSet(tag[:]), got.TestAndSet(tag[:]), "tag %d", i)
		require.Equal(t, want.Entries(), got.Entries(), "tag %d", i)
	}
}

func TestReplayFilterRoundTrip(t *testing.T) {
	f, err := newReplayFilter(rand.Reader, 12, 0.001)
	require.NoError(t, err)
	var seen [][TagLength]byte
	for i := 0; i < 100; i++ {
		var tag [TagLength]byte
		_, err := rand.Read(tag[:])
		require.NoError(t, err)
		require.False(t, f.TestAndSet(tag[:]))
		seen = append(seen, tag)
	}

	var buf bytes.Buffer
	require.NoError(t, f.writeTo(&buf))
	require.Equal(t, 16+8+(1<<12)/8, buf.Len())

	g, err := readReplayFilter(bytes.NewReader(buf.Bytes()), 12, 0.001)
	require.NoError(t, err)
	require.Equal(t, f.Entries(), g.Entries())
	for _, tag := range seen {
		require.True(t, g.TestAndSet(tag[:]))
	}
}

func TestReadReplayFilterRejectsBadInput(t *testing.T) {
	f, err := newReplayFilter(rand.Reader, 12, 0.001)
	require.NoError(t, err)
	var buf bytes.Buffer
	require.NoError(t, f.writeTo(&buf))
	good := buf.Bytes()

	_, err = readReplayFilter(bytes.NewReader(good[:len(good)-1]), 12, 0.001)
	require.Error(t, err, "truncated")
	_, err = readReplayFilter(bytes.NewReader(nil), 12, 0.001)
	require.Error(t, err, "empty")

	over := append([]byte(nil), good...)
	binary.BigEndian.PutUint64(over[16:24], uint64(f.MaxEntries()+1))
	_, err = readReplayFilter(bytes.NewReader(over), 12, 0.001)
	require.Error(t, err, "entries above capacity")
}

// SPDX-License-Identifier: AGPL-3.0-only

package mixkey

import (
	"crypto/rand"
	"os"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/nike/x25519"

	"github.com/katzenpost/katzenpost/core/sphinx/geo"
)

func persistedKey(t *testing.T) (*MixKey, *geo.Geometry, string, [TagLength]byte) {
	g := geo.GeometryFromUserForwardPayloadLength(x25519.Scheme(rand.Reader), 2000, true, 5)
	k, err := New(testEpoch, g)
	require.NoError(t, err)
	t.Cleanup(k.Deref)
	var tag [TagLength]byte
	_, err = rand.Read(tag[:])
	require.NoError(t, err)
	require.False(t, k.IsReplay(tag[:]))
	dir := t.TempDir()
	require.NoError(t, k.Persist(dir))
	return k, g, dir, tag
}

func TestPersistedKeyKeepsReplayState(t *testing.T) {
	_, g, dir, tag := persistedKey(t)

	st, err := os.Stat(keyPath(testEpoch, dir))
	require.NoError(t, err)
	if runtime.GOOS != "windows" {
		require.Equal(t, os.FileMode(0600), st.Mode().Perm())
	}

	loaded, found, err := Load(testEpoch, g, dir)
	require.NoError(t, err)
	require.True(t, found)
	defer loaded.Deref()
	require.True(t, loaded.IsReplay(tag[:]), "a tag seen before the restart is a replay after it")

	var fresh [TagLength]byte
	_, err = rand.Read(fresh[:])
	require.NoError(t, err)
	require.False(t, loaded.IsReplay(fresh[:]))
}

func TestKeyWithoutReplayStateIsNotReused(t *testing.T) {
	for name, mangle := range map[string]func([]byte) []byte{
		"truncated": func(b []byte) []byte { return b[:len(b)-1] },
		"trailing":  func(b []byte) []byte { return append(b, 0) },
		"legacy": func(b []byte) []byte {
			k, _, _, _ := persistedKey(t)
			return append([]byte("KMK1\x00"), k.nikeKeypair.Bytes()...)
		},
	} {
		t.Run(name, func(t *testing.T) {
			_, g, dir, _ := persistedKey(t)
			p := keyPath(testEpoch, dir)
			b, err := os.ReadFile(p)
			require.NoError(t, err)
			require.NoError(t, os.WriteFile(p, mangle(b), 0600))

			k, found, err := Load(testEpoch, g, dir)
			require.ErrorIs(t, err, ErrReplayStateLost)
			require.False(t, found)
			require.Nil(t, k)
			_, err = os.Stat(p)
			require.ErrorIs(t, err, os.ErrNotExist, "the unusable key is consumed")
		})
	}
}

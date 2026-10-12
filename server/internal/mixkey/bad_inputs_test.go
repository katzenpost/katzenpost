// SPDX-License-Identifier: AGPL-3.0-only

package mixkey

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/nike/x25519"

	"github.com/katzenpost/katzenpost/core/sphinx/geo"
)

func TestReplayFilterRejectsBadParameters(t *testing.T) {
	for name, tc := range map[string]struct {
		mLn2 int
		p    float64
	}{
		"rate zero":       {filterMLn2, 0},
		"rate negative":   {filterMLn2, -0.5},
		"rate one":        {filterMLn2, 1},
		"size too small":  {2, filterFPRate},
		"size too large":  {41, filterFPRate},
		"too many hashes": {10, 1e-12},
	} {
		t.Run(name, func(t *testing.T) {
			f, err := newReplayFilter(rand.Reader, tc.mLn2, tc.p)
			require.Error(t, err)
			require.Nil(t, f)
		})
	}
}

func TestMalformedKeyFileIsRefusedAndKept(t *testing.T) {
	length := func(n uint32) []byte {
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], n)
		return b[:]
	}
	header := []byte(keyFileMagic + "\x00")
	for name, body := range map[string][]byte{
		"bad magic":              []byte("KMK9\x00"),
		"truncated header":       []byte("KMK"),
		"truncated length field": append(append([]byte{}, header...), 0, 0),
		"oversized key length":   append(append([]byte{}, header...), length(maxKeyFileKeySize+1)...),
		"key shorter than length": append(append(append([]byte{}, header...), length(32)...),
			make([]byte, 10)...),
	} {
		t.Run(name, func(t *testing.T) {
			g := geo.GeometryFromUserForwardPayloadLength(x25519.Scheme(rand.Reader), 2000, true, 5)
			dir := t.TempDir()
			p := keyPath(testEpoch, dir)
			require.NoError(t, os.WriteFile(p, body, 0600))

			k, found, err := Load(testEpoch, g, dir)
			require.Error(t, err)
			require.NotErrorIs(t, err, ErrReplayStateLost)
			require.False(t, found)
			require.Nil(t, k)
			_, err = os.Stat(p)
			require.NoError(t, err, "a malformed key file is left for the operator, never reused")
		})
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, os.ErrClosed }

func TestReplayFilterIOFailures(t *testing.T) {
	_, err := readReplayFilter(bytes.NewReader(make([]byte, 16)), 10, filterFPRate)
	require.Error(t, err, "a filter cut off before its entry count is refused")

	f, err := newReplayFilter(rand.Reader, 10, filterFPRate)
	require.NoError(t, err)
	require.ErrorIs(t, f.writeTo(failWriter{}), os.ErrClosed)
}

func TestPersistReportsFilesystemFailures(t *testing.T) {
	k, _, dir, _ := persistedKey(t)
	blocker := filepath.Join(dir, "not-a-dir")
	require.NoError(t, os.WriteFile(blocker, nil, 0600))
	require.Error(t, k.Persist(filepath.Join(blocker, "keys")))
}

func TestUnconsumableKeyFileIsReported(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("directory permissions do not block removal on windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("directory permissions do not block removal for root")
	}
	g := geo.GeometryFromUserForwardPayloadLength(x25519.Scheme(rand.Reader), 2000, true, 5)
	locked := t.TempDir()
	p := keyPath(testEpoch, locked)
	require.NoError(t, os.WriteFile(p, []byte("KMK1\x00"), 0600))
	require.NoError(t, os.Chmod(locked, 0500))
	t.Cleanup(func() { os.Chmod(locked, 0700) })
	_, found, err := Load(testEpoch, g, locked)
	require.ErrorIs(t, err, ErrReplayStateLost)
	require.False(t, found)
	_, err = os.Stat(p)
	require.NoError(t, err, "a key that could not be consumed is still on disk and reported")
}

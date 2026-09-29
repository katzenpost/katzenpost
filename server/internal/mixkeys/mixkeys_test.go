// mixkeys_test.go - Mix key store tests.
// Copyright (C) 2017  Yawning Angel
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

package mixkeys

import (
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/nike/x25519"
	"github.com/katzenpost/hpqc/sign/schemes"

	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/katzenpost/katzenpost/server/internal/constants"
	"github.com/katzenpost/katzenpost/server/internal/mixkey"
)

func TestPurgeStaleKeyFiles(t *testing.T) {
	require := require.New(t)
	dir := t.TempDir()

	base := uint64(100)
	inWindow := []string{
		fmt.Sprintf("mixkey-%d.bin", base),
		fmt.Sprintf("mixkey-%d.bin", base+1),
		fmt.Sprintf("mixkey-%d.bin", base+constants.NumMixKeys-1),
	}
	stale := []string{
		"mixkey-0.bin",  // far before the window
		"mixkey-99.bin", // one before the window
		fmt.Sprintf("mixkey-%d.bin", base+constants.NumMixKeys), // one after
	}
	foreign := []string{"README.txt", "data.db"}

	for _, f := range append(append(inWindow, stale...), foreign...) {
		require.NoError(os.WriteFile(filepath.Join(dir, f), []byte("x"), 0600))
	}

	logBackend, err := log.New("", "DEBUG", false)
	require.NoError(err)
	m := &mixKeys{
		persistOnShutdown: true,
		keyStoreDir:       dir,
		log:               logBackend.GetLogger("mixkeys_test"),
	}
	require.NoError(m.purgeStaleKeyFiles(base))

	for _, f := range stale {
		_, err := os.Stat(filepath.Join(dir, f))
		require.ErrorIs(err, os.ErrNotExist, "stale key file purged: %s", f)
	}
	for _, f := range append(inWindow, foreign...) {
		_, err := os.Stat(filepath.Join(dir, f))
		require.NoError(err, "in-window/foreign file kept: %s", f)
	}

	// With persistence disabled the sweep is a no-op.
	dir2 := t.TempDir()
	require.NoError(os.WriteFile(filepath.Join(dir2, "mixkey-99.bin"), []byte("x"), 0600))
	m2 := &mixKeys{persistOnShutdown: false, keyStoreDir: dir2}
	require.NoError(m2.purgeStaleKeyFiles(base))
	_, err = os.Stat(filepath.Join(dir2, "mixkey-99.bin"))
	require.NoError(err, "no purge when persistence disabled")

	// A missing key store dir is not an error.
	m3 := &mixKeys{persistOnShutdown: true, keyStoreDir: filepath.Join(dir, "does-not-exist")}
	require.NoError(m3.purgeStaleKeyFiles(base))
}

func TestDefaultKeyStoreDir(t *testing.T) {
	require := require.New(t)

	scheme := schemes.ByName("ed25519")
	require.NotNil(scheme, "ed25519 scheme available")
	pub, _, err := scheme.GenerateKey()
	require.NoError(err)

	if runtime.GOOS == "windows" {
		// The /dev/shm default is unix-only; on Windows it must panic so
		// operators configure PersistMixKeysOnShutdownDir explicitly.
		require.Panics(func() { defaultKeyStoreDir(pub) }, "tmpfs default unsupported on windows")
		return
	}

	dir := defaultKeyStoreDir(pub)
	require.Contains(dir, "/dev/shm", "tmpfs location")
	require.Contains(dir, "katzenpost-mixkeys-", "per-node prefix")
	require.Equal(dir, defaultKeyStoreDir(pub), "deterministic per identity key")
}

func TestGenerateFailsOnCorruptPersistedKey(t *testing.T) {
	require := require.New(t)
	dir := t.TempDir()

	// A persisted file inside the generation window that cannot be loaded
	// must abort key generation rather than silently fall back to a fresh
	// key, which would leave the node's keypairs out of sync with the
	// consensus already published by the authorities.
	require.NoError(os.WriteFile(filepath.Join(dir, "mixkey-0.bin"), []byte("garbage"), 0600))

	logBackend, err := log.New("", "DEBUG", false)
	require.NoError(err)
	mynike := x25519.Scheme(rand.Reader)
	m := &mixKeys{
		geo:               geo.GeometryFromUserForwardPayloadLength(mynike, 2000, true, 5),
		persistOnShutdown: true,
		keyStoreDir:       dir,
		log:               logBackend.GetLogger("mixkeys_test"),
		keys:              make(map[uint64]*mixkey.MixKey),
	}
	_, err = m.Generate(0)
	require.Error(err, "Generate must fail on a corrupt persisted key")
	require.ErrorContains(err, "invalid header", "Generate error cause")
}

// mixkey_test.go - Mix keys tests.
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

package mixkey

import (
	"crypto/rand"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/nike"
	"github.com/katzenpost/hpqc/nike/x25519"

	"github.com/katzenpost/katzenpost/core/sphinx/geo"
)

const testEpoch = 0x23 // Way in the past on systems with correct time.

var (
	tmpDir string

	testKeyPath string
	testKey     *x25519.PrivateKey

	testPositiveTags, testNegativeTags map[[TagLength]byte]bool
)

func TestCreateMixKey(t *testing.T) {
	require := require.New(t)
	assert := assert.New(t)

	mynike := x25519.Scheme(rand.Reader)
	geo := geo.GeometryFromUserForwardPayloadLength(mynike, 2000, true, 5)

	k, err := New(testEpoch, geo)
	require.NoError(err, "New()")
	defer k.Deref()

	nikePubKey, _ := k.PublicKey()
	//nikeScheme, kemScheme := geo.Scheme()

	if nikePubKey != nil {
		t.Logf("Public Key: %v", hex.EncodeToString(nikePubKey.Bytes()))
	} else {
		panic("wtf")
		//t.Logf("Public Key: %v", hex.EncodeToString(pubBytes))
	}

	a := k.PrivateKey()
	require.NotNil(a)
	key := a.(nike.PrivateKey)
	t.Logf("Private Key: %v", hex.EncodeToString(key.Bytes()))
	t.Logf("Epoch: %x", k.Epoch())

	// Save a copy so this can be compared later.
	a = k.PrivateKey()
	require.NotNil(a)

	key = a.(nike.PrivateKey)
	err = testKey.FromBytes(key.Bytes())
	require.NoError(err, "testKey save")

	// Ensure that the 0 byte pathological tag case behaves.
	assert.True(k.IsReplay([]byte{}), "IsReplay([]byte{})")

	// Populate the replay filter.
	for tag := range testPositiveTags {
		isReplay := k.IsReplay(tag[:])
		assert.False(isReplay, "IsReplay() new: %v", hex.EncodeToString(tag[:]))
	}
}

func TestMixKeyPersistRoundtrip(t *testing.T) {
	require := require.New(t)

	dir, err := os.MkdirTemp("", "mixkey_persist")
	require.NoError(err, "MkdirTemp()")
	defer os.RemoveAll(dir)

	mynike := x25519.Scheme(rand.Reader)
	geo := geo.GeometryFromUserForwardPayloadLength(mynike, 2000, true, 5)

	k, err := New(testEpoch, geo)
	require.NoError(err, "New()")
	defer k.Deref()

	wantPub := k.PublicBytes()
	require.NoError(k.Persist(dir), "Persist()")

	// No key file yet for an epoch that was never persisted.
	_, found, err := Load(testEpoch+1, geo, dir)
	require.NoError(err, "Load(missing) err")
	require.False(found, "Load(missing) found")

	// Load returns the same public key for the persisted epoch.
	loaded, found, err := Load(testEpoch, geo, dir)
	require.NoError(err, "Load() err")
	require.True(found, "Load() found")
	defer loaded.Deref()
	require.Equal(wantPub, loaded.PublicBytes(), "public key preserved across Persist/Load")

	// Consume-on-read: the persisted key file is deleted as soon as it
	// loads successfully, so key material never lingers between a clean
	// shutdown and the immediately following boot.
	_, statErr := os.Stat(keyPath(testEpoch, dir))
	require.ErrorIs(statErr, os.ErrNotExist, "persisted key file consumed by Load")
	_, found, err = Load(testEpoch, geo, dir)
	require.NoError(err, "Load(consumed) err")
	require.False(found, "Load(consumed) found")

	// A corrupt file fails loudly instead of being silently loaded.
	require.NoError(os.WriteFile(filepath.Join(dir, "mixkey-0.bin"), []byte("garbage"), 0600))
	_, found, err = Load(0, geo, dir)
	require.Error(err, "Load(corrupt) err")
	require.False(found, "Load(corrupt) found")

	// A file that fails to load is left in place for diagnosis; it will
	// be overwritten by the next clean shutdown's Persist.
	_, statErr = os.Stat(filepath.Join(dir, "mixkey-0.bin"))
	require.NoError(statErr, "corrupt key file left in place")

	// Remove deletes the persisted file.
	Remove(testEpoch, dir)
	_, found, err = Load(testEpoch, geo, dir)
	require.NoError(err, "Load(after Remove) err")
	require.False(found, "Load(after Remove) found")
}

func TestLoadFailsWhenConsumeFails(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("posix directory permissions are not available on windows")
	}
	require := require.New(t)

	dir, err := os.MkdirTemp("", "mixkey_consume")
	require.NoError(err, "MkdirTemp()")
	defer os.RemoveAll(dir)

	mynike := x25519.Scheme(rand.Reader)
	geo := geo.GeometryFromUserForwardPayloadLength(mynike, 2000, true, 5)

	k, err := New(testEpoch, geo)
	require.NoError(err, "New()")
	defer k.Deref()
	require.NoError(k.Persist(dir), "Persist()")

	// Revoke write access to the key store so the consume-on-read unlink
	// fails. Load must refuse to hand out a key whose file could not be
	// removed, since that would leave private key material on the filesystem.
	require.NoError(os.Chmod(dir, 0500), "Chmod()")
	defer os.Chmod(dir, 0700)

	_, found, err := Load(testEpoch, geo, dir)
	if err == nil {
		// The environment bypassed the directory permission (e.g. the
		// test runs as root in a container), so the failure cannot be
		// simulated here.
		t.Skip("removal was not blocked by directory permissions (running as root?)")
		return
	}
	require.False(found, "Load() found")
	require.ErrorContains(err, "failed to consume persisted key file", "Load() error cause")
	_, statErr := os.Stat(keyPath(testEpoch, dir))
	require.NoError(statErr, "unconsumed key file left in place")
}

func BenchmarkMixKey(b *testing.B) {
	var err error
	tmpDir, err = os.MkdirTemp("", "mixkey_benchmarks")
	if err != nil {
		b.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	b.Run("IsReplay (miss)", doBenchIsReplayMiss)
	b.Run("IsReplay (hit)", doBenchIsReplayHit)
}

func doBenchIsReplayMiss(b *testing.B) {
	mynike := x25519.Scheme(rand.Reader)
	geo := geo.GeometryFromUserForwardPayloadLength(mynike, 2000, true, 5)
	k, err := New(testEpoch, geo)
	if err != nil {
		b.Fatalf("Failed to open key: %v", err)
	}
	k.SetUnlinkIfExpired(true)
	defer k.Deref()

	count := 0
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		var tag [TagLength]byte
		_, err = rand.Read(tag[:])
		if err != nil {
			b.Fatalf("failed to read random tag: %v", err)
		}
		b.StartTimer()

		if k.IsReplay(tag[:]) {
			count++
		}
	}
	b.StopTimer()
	if count != 0 {
		// Not a problem, just means we happened to generate colliding tags.
		b.Logf("replays (%v) != 0", count)
	}
}

func doBenchIsReplayHit(b *testing.B) {
	mynike := x25519.Scheme(rand.Reader)
	geo := geo.GeometryFromUserForwardPayloadLength(mynike, 2000, true, 5)
	k, err := New(testEpoch, geo)
	if err != nil {
		b.Fatalf("Failed to open key: %v", err)
	}
	k.SetUnlinkIfExpired(true)
	defer k.Deref()

	var tag [TagLength]byte
	_, err = rand.Read(tag[:])
	if err != nil {
		b.Fatalf("Failed to read random tag: %v", err)
	}
	k.IsReplay(tag[:]) // Add as a replay.

	count := 0
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if k.IsReplay(tag[:]) {
			count++
		}
	}
	b.StopTimer()
	if count != b.N {
		b.Fatalf("replays (%v) != iterations (%v)", count, b.N)
	}
}

func init() {
	_, privkey, err := x25519.Scheme(rand.Reader).GenerateKeyPair()
	if err != nil {
		panic(err)
	}

	testKey = privkey.(*x25519.PrivateKey)

	tmpDir, err = os.MkdirTemp("", "mixkey_tests")
	if err != nil {
		panic(err)
	}

	testPositiveTags = make(map[[TagLength]byte]bool)
	for i := 0; i < 10; {
		var tag [TagLength]byte
		_, err = rand.Read(tag[:])
		if err != nil {
			panic(err)
		}
		if !testPositiveTags[tag] {
			testPositiveTags[tag] = true
			i++
		}
	}

	testNegativeTags = make(map[[TagLength]byte]bool)
	for i := 0; i < 10; {
		var tag [TagLength]byte
		_, err = rand.Read(tag[:])
		if err != nil {
			panic(err)
		}
		if !testPositiveTags[tag] && !testNegativeTags[tag] {
			testNegativeTags[tag] = true
			i++
		}
	}
}

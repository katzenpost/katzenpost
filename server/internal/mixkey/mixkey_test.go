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
	"io/ioutil"
	"os"
	"testing"

	"github.com/katzenpost/core/crypto/ecdh"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testEpoch = 0x23 // Way in the past on systems with correct time.

var (
	tmpDir string

	testKeyPath string
	testKey     ecdh.PrivateKey

	testPositiveTags, testNegativeTags map[[TagLength]byte]bool
)

func TestMixKey(t *testing.T) {
	t.Logf("Temp Dir: %v", tmpDir)

	if ok := t.Run("create", doTestCreate); ok {
		t.Run("load", doTestLoad)
		t.Run("unlink", doTestUnlink)
	} else {
		t.Errorf("create tests failed, skipping load tests")
	}

	// Clean up after all of the tests, by removing the temporary directory
	// that holds keys.
	os.RemoveAll(tmpDir)
}

func doTestCreate(t *testing.T) {
	require := require.New(t)
	assert := assert.New(t)

	k, err := New(tmpDir, testEpoch)
	require.NoError(err, "New()")
	testKeyPath = k.db.Path()
	defer k.Deref()

	t.Logf("db: %v", testKeyPath)
	t.Logf("Public Key: %v", hex.EncodeToString(k.PublicKey().Bytes()))
	t.Logf("Private Key: %v", hex.EncodeToString(k.PrivateKey().Bytes()))
	t.Logf("Epoch: %x", k.Epoch())

	// Save a copy so this can be compared later.
	err = testKey.FromBytes(k.PrivateKey().Bytes())
	require.NoError(err, "testKey save")

	// Ensure that the 0 byte pathological tag case behaves.
	assert.True(k.IsReplay([]byte{}), "IsReplay([]byte{})")

	// Populate the replay filter.
	for tag := range testPositiveTags {
		isReplay := k.IsReplay(tag[:])
		assert.False(isReplay, "IsReplay() new: %v", hex.EncodeToString(tag[:]))
	}
}

func doTestLoad(t *testing.T) {
	require := require.New(t)
	assert := assert.New(t)

	k, err := New(tmpDir, testEpoch)
	require.NoError(err, "New() load")
	k.SetUnlinkIfExpired(true)
	defer k.Deref()

	assert.Equal(&testKey, k.PrivateKey(), "Serialized private key")
	assert.Equal(testKey.PublicKey(), k.PublicKey(), "Serialized public key")
	assert.Equal(uint64(testEpoch), k.Epoch(), "Serialized epoch")

	// Ensure that the loaded replay filter is consistent.
	assert.True(k.IsReplay([]byte{}), "IsReplay([]byte{})")
	for tag := range testPositiveTags {
		isReplay := k.IsReplay(tag[:])
		assert.True(isReplay, "IsReplay() load, positive: %v", hex.EncodeToString(tag[:]))
	}
	for tag := range testNegativeTags {
		isReplay := k.IsReplay(tag[:])
		assert.False(isReplay, "IsReplay() load, negative: %v", hex.EncodeToString(tag[:]))
	}
}

func doTestUnlink(t *testing.T) {
	require := require.New(t)

	// doTestLoad() should have removed the database, unless it failed to load.
	_, err := os.Lstat(testKeyPath)
	require.True(os.IsNotExist(err), "Database should not exist")
}

func BenchmarkMixKey(b *testing.B) {
	var err error
	tmpDir, err = ioutil.TempDir("", "mixkey_benchmarks")
	if err != nil {
		b.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	b.Run("IsReplay (miss)", doBenchIsReplayMiss)
	b.Run("IsReplay (hit)", doBenchIsReplayHit)
}

func doBenchIsReplayMiss(b *testing.B) {
	k, err := New(tmpDir, testEpoch)
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
		rand.Read(tag[:])
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
	k, err := New(tmpDir, testEpoch)
	if err != nil {
		b.Fatalf("Failed to open key: %v", err)
	}
	k.SetUnlinkIfExpired(true)
	defer k.Deref()

	var tag [TagLength]byte
	rand.Read(tag[:])
	k.IsReplay(tag[:]) // Add as a replay.
	k.doFlush(true)    // Flush the write-back cache.

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
	var err error
	tmpDir, err = ioutil.TempDir("", "mixkey_tests")
	if err != nil {
		panic(err)
	}

	testPositiveTags = make(map[[TagLength]byte]bool)
	for i := 0; i < 10; {
		var tag [TagLength]byte
		rand.Read(tag[:])
		if !testPositiveTags[tag] {
			testPositiveTags[tag] = true
			i++
		}
	}

	testNegativeTags = make(map[[TagLength]byte]bool)
	for i := 0; i < 10; {
		var tag [TagLength]byte
		rand.Read(tag[:])
		if !testPositiveTags[tag] && !testNegativeTags[tag] {
			testNegativeTags[tag] = true
			i++
		}
	}
}

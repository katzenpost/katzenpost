// boltuserdb_test.go - boltspool tests.
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

package boltspool

import (
	"crypto/rand"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/katzenpost/core/constants"
	sConstants "github.com/katzenpost/core/sphinx/constants"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	testSpool = "spool.db"
	testUser  = "allan"
)

var (
	tmpDir        string
	testSpoolPath string

	testMsg     []byte
	testSurbID  [sConstants.SURBIDLength]byte
	testSurbMsg []byte
)

func TestBoltSpool(t *testing.T) {
	require := require.New(t)

	t.Logf("TempDir: %v", tmpDir)

	// Build a test message.
	testMsg = make([]byte, constants.UserForwardPayloadLength)
	_, err := rand.Read(testMsg)
	require.NoError(err, "rand.Read(testMsg)")

	// Built a test SURBReply.
	_, err = rand.Read(testSurbID[:])
	require.NoError(err, "rand.Read(testSurbID)")
	testSurbMsg = make([]byte, constants.ForwardPayloadLength)
	_, err = rand.Read(testSurbMsg)
	require.NoError(err, "rand.Read(testSurbMsg)")

	if ok := t.Run("create", doTestCreate); ok {
		t.Run("load", doTestLoad)
	} else {
		t.Errorf("create tests failed, skipping load test")
	}

	os.RemoveAll(tmpDir)
}

func doTestCreate(t *testing.T) {
	require := require.New(t)
	assert := assert.New(t)

	s, err := New(testSpoolPath)
	require.NoError(err, "New()")
	defer s.Close()

	err = s.StoreMessage([]byte(testUser), testMsg)
	assert.NoError(err, "StoreMessage()")

	err = s.StoreSURBReply([]byte(testUser), &testSurbID, testSurbMsg)
	assert.NoError(err, "StoreSURBReply()")
}

func doTestLoad(t *testing.T) {
	require := require.New(t)
	assert := assert.New(t)

	s, err := New(testSpoolPath)
	require.NoError(err, "New()")
	defer s.Close()

	// Query 0th message without discard.
	msg, id, remaining, err := s.Get([]byte(testUser), false)
	assert.NoError(err, "Get(): testMsg")
	assert.Equal(testMsg, msg, "Loaded Message")
	assert.Nil(id, "Message should have no SURB ID")
	assert.Equal(1, remaining, "Should be 1 since there's more in the queue")

	// Query the 0th message with discard, and then without.  Both cases
	// should return the SURBReply,
	for i := 0; i < 2; i++ {
		msg, id, remaining, err = s.Get([]byte(testUser), i != 1)
		assert.NoError(err, "Get(): testSurbMsg")
		assert.Equal(testSurbMsg, msg, "Loaded SURBReply")
		assert.Equal(testSurbID[:], id, "Loaded SURB ID")
		assert.Equal(0, remaining, "Should be 0 since the SURBReply is the only entry")
	}

	// Query the 0th message with discard, should be an empty queue since the
	// SURBReply will be discarded.
	msg, id, remaining, err = s.Get([]byte(testUser), true)
	assert.NoError(err, "Get(): discard -> empty")
	assert.Nil(msg, "Loaded Empty")
	assert.Nil(id, "Loaded Empty SURB ID")
	assert.Equal(0, remaining, "Should be 0 since the queue is empty")

	// Delete the user's spool.
	err = s.Remove([]byte(testUser))
	assert.NoError(err, "Delete(u)")
}

func init() {
	var err error
	tmpDir, err = ioutil.TempDir("", "boltspool_tests")
	if err != nil {
		panic(err)
	}

	testSpoolPath = filepath.Join(tmpDir, testSpool)
}

// boltuserdb_test.go - boltuserdb tests.
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

package boltuserdb

import (
	"crypto/rand"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/wire"
)

const testDB = "userdb.db"

var (
	tmpDir     string
	testDBPath string

	testUsernames = []string{"alice", "bob"}
	testUsers     map[string]wire.PublicKey
)

func TestBoltUserDB(t *testing.T) {
	t.Logf("Temp Dir: %v", tmpDir)
	defer os.RemoveAll(tmpDir)

	ok := t.Run("createTOFU", doTestCreateWithTOFU)
	if !ok {
		t.Errorf("test failed, skipping load test")
		return
	}

	ok = t.Run("loadTOFU", doTestLoadTOFU)
	if !ok {
		t.Errorf("test failed, skipping load test")
		return
	}

	os.RemoveAll(testDBPath)

	ok = t.Run("create", doTestCreate)
	if !ok {
		t.Errorf("test failed, skipping load test")
		return
	}

	ok = t.Run("load", doTestLoad)
	if !ok {
		t.Errorf("test failed, skipping load test")
		return
	}
}

func doTestCreateWithTOFU(t *testing.T) {
	require := require.New(t)
	assert := assert.New(t)

	d, err := New(testDBPath, WithTrustOnFirstUse())
	require.NoError(err, "New()")
	defer d.Close()

	for u, k := range testUsers {
		err = d.Add([]byte(u), k, false)
		require.NoErrorf(err, "Add(%v, k, false)", u)
	}

	scheme := wire.DefaultScheme
	wrongPrivKey := scheme.GenerateKeypair(rand.Reader)
	wrongPubKey := wrongPrivKey.PublicKey()

	for u, k := range testUsers {
		assert.True(d.Exists([]byte(u)), "Exists('%s')", u)
		assert.True(d.IsValid([]byte(u), k), "IsValid('%s', k)", u)
		assert.False(d.IsValid([]byte(u), wrongPubKey))
	}

	assert.False(d.Exists([]byte("malory_create_tofu")))
	assert.True(d.IsValid([]byte("malory_create_tofu"), testUsers["alice"]))
	assert.True(d.Exists([]byte("malory_create_tofu")))
	assert.False(d.IsValid([]byte("malory_create_tofu"), wrongPubKey))
}

func doTestCreate(t *testing.T) {
	require := require.New(t)
	assert := assert.New(t)

	d, err := New(testDBPath)
	require.NoError(err, "New()")
	defer d.Close()

	for u, k := range testUsers {
		err = d.Add([]byte(u), k, false)
		require.NoErrorf(err, "Add(%v, k, false)", u)
	}

	for u, k := range testUsers {
		assert.True(d.Exists([]byte(u)), "Exists('%s')", u)
		assert.True(d.IsValid([]byte(u), k), "IsValid('%s', k)", u)
	}
	assert.False(d.Exists([]byte("wrong")))
	assert.False(d.IsValid([]byte("wrong"), testUsers["alice"]))
}

func doTestLoadTOFU(t *testing.T) {
	require := require.New(t)
	assert := assert.New(t)

	d, err := New(testDBPath, WithTrustOnFirstUse())
	require.NoError(err, "New() load")
	defer d.Close()

	scheme := wire.DefaultScheme
	wrongPrivKey := scheme.GenerateKeypair(rand.Reader)
	wrongPubKey := wrongPrivKey.PublicKey()

	for u, k := range testUsers {
		assert.True(d.Exists([]byte(u)), "Exists('%s')", u)
		assert.True(d.IsValid([]byte(u), k), "IsValid('%s', k)", u)
		assert.False(d.IsValid([]byte(u), wrongPubKey))
	}
	assert.False(d.Exists([]byte("malory_load")))
	assert.True(d.IsValid([]byte("malory_load"), testUsers["alice"]))
	assert.False(d.IsValid([]byte("malory_load"), wrongPubKey))

	err = d.Add([]byte("alice"), testUsers["alice"], false)
	assert.Error(err, "Add('alice', k, false)")
}

func doTestLoad(t *testing.T) {
	require := require.New(t)
	assert := assert.New(t)

	d, err := New(testDBPath)
	require.NoError(err, "New() load")
	defer d.Close()

	for u, k := range testUsers {
		assert.True(d.Exists([]byte(u)), "Exists('%s')", u)
		assert.True(d.IsValid([]byte(u), k), "IsValid('%s', k)", u)
	}
	assert.False(d.Exists([]byte("verywrongly")))
	assert.False(d.IsValid([]byte("verywrongly"), testUsers["alice"]))

	err = d.Add([]byte("alice"), testUsers["alice"], false)
	assert.Error(err, "Add('alice', k, false)")
}

func init() {
	var err error
	tmpDir, err = ioutil.TempDir("", "boltuserdb_tests")
	if err != nil {
		panic(err)
	}
	testDBPath = filepath.Join(tmpDir, testDB)
	testUsers = make(map[string]wire.PublicKey)
	for _, v := range testUsernames {
		scheme := wire.DefaultScheme
		privKey := scheme.GenerateKeypair(rand.Reader)
		testUsers[v] = privKey.PublicKey()
	}
}

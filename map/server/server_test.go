// server_test.go - map service using cbor plugin system
// Copyright (C) 2021  Masala
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

package server

import (
	"io/ioutil"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/katzenpost/hpqc/rand"
	"github.com/katzenpost/hpqc/sign/ed25519"
	"github.com/katzenpost/katzenpost/map/common"
	"github.com/stretchr/testify/require"
	"gopkg.in/op/go-logging.v1"
)

func TestCreateMap(t *testing.T) {

	if runtime.GOOS == "windows" {
		return
	}

	require := require.New(t)
	tmpDir, err := ioutil.TempDir("", "map_test")
	require.NoError(err)
	f := filepath.Join(tmpDir, "map.store")
	log := logging.MustGetLogger("map")
	m, err := NewMap(f, log, 10, 100)
	require.NoError(err)
	m.Halt()

	// clean up
	err = os.RemoveAll(tmpDir)
	require.NoError(err)
}

func TestMap(t *testing.T) {

	if runtime.GOOS == "windows" {
		return
	}

	// start a map service
	require := require.New(t)
	tmpDir, err := ioutil.TempDir("", "map_test")
	require.NoError(err)
	f := filepath.Join(tmpDir, "map.store")
	log := logging.MustGetLogger("map")
	m, err := NewMap(f, log, 10, 100)
	require.NoError(err)

	// put data in a key
	var msgID common.MessageID
	_, err = rand.Reader.Read(msgID[:])
	require.NoError(err)
	payload := []byte("hola")

	err = m.Put(msgID, payload)
	require.NoError(err)

	// read data from key
	data, err := m.Get(msgID)
	require.NoError(err)

	// verify the key was retrieved
	require.Equal(data, payload)

	m.Shutdown()

	// restart the server
	m, err = NewMap(f, log, 10, 100)

	// verify the data is still there
	data, err = m.Get(msgID)
	require.Equal(data, payload)

	// clean up
	err = os.RemoveAll(tmpDir)
	require.NoError(err)
}

func TestGarbageCollect(t *testing.T) {
	// start a map service
	require := require.New(t)
	tmpDir, err := ioutil.TempDir("", "map_test")
	require.NoError(err)
	//defer os.RemoveAll(tmpDir)
	f := filepath.Join(tmpDir, "map.store")
	log := logging.MustGetLogger("map")

	// garbage collection parameters
	gcsize := 10
	mapsize := 100

	m, err := NewMap(f, log, gcsize, mapsize)
	require.NoError(err)

	msgIDs := make([]common.MessageID, mapsize+1)
	// fill map to mapSize + 1 to trigger GarbageCollection
	for i := 0; i < mapsize+1; i++ {
		var msgID common.MessageID
		_, err = rand.Reader.Read(msgID[:])
		require.NoError(err)
		payload := []byte("hola")
		err = m.Put(msgID, payload)
		require.NoError(err)

		// keep ordered list of msgID
		msgIDs[i] = msgID
	}

	// verify that the keys are available
	for i := 0; i < gcsize; i++ {
		d, err := m.Get(msgIDs[i])
		require.NoError(err)
		require.Equal(d, []byte("hola"))
	}
	err = m.GarbageCollect()
	require.NoError(err)

	// verify that the keys are gone
	for i := 0; i < gcsize; i++ {
		_, err := m.Get(msgIDs[i])
		require.Error(err)
	}

	// verify that the next gcsize keys are still there
	for i := gcsize; i < 2*gcsize; i++ {
		d, err := m.Get(msgIDs[i])
		require.NoError(err)
		require.Equal(d, []byte("hola"))
	}

	m.Shutdown()

	// clean up
	err = os.RemoveAll(tmpDir)
	require.NoError(err)
}

func TestValidateRWCap(t *testing.T) {
	require := require.New(t)
	sk, _, err := ed25519.NewKeypair(rand.Reader)
	require.NoError(err)

	cap_rw := common.NewRWCap(sk)
	addr := []byte("address we want to read")
	payload := []byte("here are some bytes to write")

	mID := cap_rw.Addr(addr)
	wKey := cap_rw.WriteKey(addr)
	rKey := cap_rw.ReadKey(addr)
	wSignature := wKey.Sign(payload)
	rSignature := rKey.Sign(mID.Bytes())
	// test verification of write
	require.True(validateCap(&common.MapRequest{ID: mID, Signature: wSignature, Payload: payload}))
	// test failure of write
	require.False(validateCap(&common.MapRequest{ID: mID, Signature: wSignature, Payload: payload[:len(payload)-2]}))

	// test verification of read
	require.True(validateCap(&common.MapRequest{ID: mID, Signature: rSignature, Payload: []byte{}}))

	// test failure of read
	require.False(validateCap(&common.MapRequest{ID: mID, Signature: rSignature, Payload: payload[:len(payload)-1]}))
}

func TestValidateROCap(t *testing.T) {
	require := require.New(t)
	sk, _, err := ed25519.NewKeypair(rand.Reader)
	require.NoError(err)

	cap_rw := common.NewRWCap(sk)
	cap_ro := cap_rw.ReadOnly()
	addr := []byte("address we want to read")

	mID := cap_ro.Addr(addr)
	rKey := cap_ro.ReadKey(addr)
	rSignature := rKey.Sign(mID.Bytes())

	// test verification of read
	require.True(validateCap(&common.MapRequest{ID: mID, Signature: rSignature, Payload: []byte{}}))

	// test failure of read
	require.False(validateCap(&common.MapRequest{ID: mID, Signature: rSignature[:len(rSignature)-1], Payload: []byte{}}))
}

func TestValidateWOCap(t *testing.T) {
	require := require.New(t)
	sk, _, err := ed25519.NewKeypair(rand.Reader)
	require.NoError(err)

	cap_rw := common.NewRWCap(sk)
	cap_wo := cap_rw.WriteOnly()
	addr := []byte("address we want to read")
	payload := []byte("here are some bytes to write")

	mID := cap_wo.Addr(addr)
	wKey := cap_wo.WriteKey(addr)
	wSignature := wKey.Sign(payload)

	// test verification of write
	require.True(validateCap(&common.MapRequest{ID: mID, Signature: wSignature, Payload: payload}))

	// test failure of write
	require.False(validateCap(&common.MapRequest{ID: mID, Signature: wSignature, Payload: payload[:len(payload)-1]}))
}

// server_test.go - scratch service using cbor plugin system
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
	"github.com/stretchr/testify/require"
	"gopkg.in/op/go-logging.v1"
)

func TestCreateScratch(t *testing.T) {

	if runtime.GOOS == "windows" {
		return
	}

	require := require.New(t)
	tmpDir, err := ioutil.TempDir("", "scratch_test")
	require.NoError(err)
	f := filepath.Join(tmpDir, "scratch.store")
	log := logging.MustGetLogger("scratch")
	m, err := NewScratch(f, log, 10, 100)
	require.NoError(err)
	m.Halt()

	// clean up
	err = os.RemoveAll(tmpDir)
	require.NoError(err)
}

func TestScratch(t *testing.T) {

	if runtime.GOOS == "windows" {
		return
	}

	// start a scratch service
	require := require.New(t)
	tmpDir, err := ioutil.TempDir("", "scratch_test")
	require.NoError(err)
	f := filepath.Join(tmpDir, "scratch.store")
	log := logging.MustGetLogger("scratch")
	m, err := NewScratch(f, log, 10, 100)
	require.NoError(err)

	// generate a new signing key
	secretKey, pubKey, err := ed25519.NewKeypair(rand.Reader)
	require.NoError(err)

	// create and sign a payload
	payload := []byte("hola")
	sig := secretKey.SignMessage(payload)
	sig64 := new([ed25519.SignatureSize]byte)
	copy(sig64[:], sig)

	msgID := pubKey.ByteArray()

	// send the payload
	err = m.Put(&msgID, payload, sig64)
	require.NoError(err)

	// read data from key
	data, sig64, err := m.Get(&msgID)
	require.NoError(err)

	// verify the key was retrieved
	require.Equal(data, payload)

	m.Shutdown()

	// restart the server
	m, err = NewScratch(f, log, 10, 100)

	// verify the data is still there
	data, sig64, err = m.Get(&msgID)
	require.Equal(data, payload)

	// clean up
	err = os.RemoveAll(tmpDir)
	require.NoError(err)
}

func TestGarbageCollect(t *testing.T) {
	// start a scratch service
	require := require.New(t)
	tmpDir, err := ioutil.TempDir("", "scratch_test")
	require.NoError(err)
	//defer os.RemoveAll(tmpDir)
	f := filepath.Join(tmpDir, "scratch.store")
	log := logging.MustGetLogger("scratch")

	// garbage collection parameters
	gcsize := 10
	scratchSize := 100

	m, err := NewScratch(f, log, gcsize, scratchSize)
	require.NoError(err)

	msgIDs := make([][ed25519.PublicKeySize]byte, scratchSize+1)
	// fill scratch to scratchSize + 1 to trigger GarbageCollection
	for i := 0; i < scratchsize+1; i++ {

		secretKey, pubKey, err := ed25519.NewKeypair(rand.Reader)
		msgID := pubKey.ByteArray()
		payload := []byte("hola")
		sig := secretKey.SignMessage(payload)
		sig64 := new([ed25519.SignatureSize]byte)
		copy(sig64[:], sig)
		err = m.Put(&msgID, payload, sig64)
		require.NoError(err)

		// keep ordered list of msgID
		msgIDs[i] = msgID
	}

	// verify that the keys are available
	for i := 0; i < gcsize; i++ {
		d, _, err := m.Get(&msgIDs[i])
		require.NoError(err)
		require.Equal(d, []byte("hola"))
	}
	err = m.GarbageCollect()
	require.NoError(err)

	// verify that the keys are gone
	for i := 0; i < gcsize; i++ {
		_, _, err := m.Get(&msgIDs[i])
		require.Error(err)
	}

	// verify that the next gcsize keys are still there
	for i := gcsize; i < 2*gcsize; i++ {
		d, _, err := m.Get(&msgIDs[i])
		require.NoError(err)
		require.Equal(d, []byte("hola"))
	}

	m.Shutdown()

	// clean up
	err = os.RemoveAll(tmpDir)
	require.NoError(err)
}

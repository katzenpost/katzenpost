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
	"github.com/katzenpost/katzenpost/core/crypto/rand"
	"github.com/katzenpost/katzenpost/map/common"
	"github.com/stretchr/testify/require"
	"gopkg.in/op/go-logging.v1"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"
)

func TestCreateMap(t *testing.T) {
	require := require.New(t)
	tmpDir := t.TempDir()
	f := filepath.Join(tmpDir, "map.store")
	log := logging.MustGetLogger("map")
	m, err := NewMap(f, log, 10, 100)
	require.NoError(err)
	m.Halt()
}

func TestMap(t *testing.T) {
	// start a map service
	require := require.New(t)
	tmpDir := t.TempDir()
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
	require.NoError(err)

	// verify the data is still there
	data, err = m.Get(msgID)
	require.Equal(data, payload)
	require.NoError(err)
}

func TestGarbageCollect(t *testing.T) {
	// start a map service
	require := require.New(t)
	tmpDir := t.TempDir()
	f := filepath.Join(tmpDir, "map.store")
	log := logging.MustGetLogger("map")

	// garbage collection parameters
	gcsize := 10
	mapsize := 100

	m, err := NewMap(f, log, gcsize, mapsize)
	require.NoError(err)

	msgIDs := make([]common.MessageID, mapsize+1)
	// fill map to mapSize + 1 to trigger GarbageCollection
	for i := 0; i< mapsize + 1; i++ {
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
	for i := 0; i < gcsize; i ++ {
		d, err := m.Get(msgIDs[i])
		require.NoError(err)
		require.Equal(d, []byte("hola"))
	}
	err = m.GarbageCollect()
	require.NoError(err)

	// verify that the keys are gone
	for i := 0; i < gcsize; i ++ {
		_, err := m.Get(msgIDs[i])
		require.Error(err)
	}

	// verify that the next gcsize keys are still there
	for i := gcsize; i < 2*gcsize; i ++ {
		d, err := m.Get(msgIDs[i])
		require.NoError(err)
		require.Equal(d, []byte("hola"))
	}

	m.Shutdown()
}

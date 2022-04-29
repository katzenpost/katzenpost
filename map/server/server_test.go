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
	tmpDir, err := ioutil.TempDir("", "map_test")
	require.NoError(err)
	f := filepath.Join(tmpDir, "map.store")
	log := logging.MustGetLogger("map")
	m, err := NewMap(f, log)
	require.NoError(err)
	m.Halt()

	// clean up
	err = os.RemoveAll(tmpDir)
	require.NoError(err)
}

func TestMap(t *testing.T) {
	// start a map service
	require := require.New(t)
	tmpDir, err := ioutil.TempDir("", "map_test")
	require.NoError(err)
	f := filepath.Join(tmpDir, "map.store")
	log := logging.MustGetLogger("map")
	m, err := NewMap(f, log)
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

	// verify the key was retrieved
	require.Equal(data, payload)

	m.Shutdown()

	// restart the server
	m, err = NewMap(f, log)

	// verify the data is still there
	data, err = m.Get(msgID)
	require.Equal(data, payload)

	// clean up
	err = os.RemoveAll(tmpDir)
	require.NoError(err)
}

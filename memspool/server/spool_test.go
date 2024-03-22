// spool.go - memspool
// Copyright (C) 2019  David Stainton.
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
	"os"
	"testing"

	"github.com/stretchr/testify/assert"

	ecdh "github.com/katzenpost/hpqc/nike/x25519"
	"github.com/katzenpost/hpqc/rand"
	eddsa "github.com/katzenpost/hpqc/sign/ed25519"

	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/katzenpost/katzenpost/memspool/common"
)

func TestSpool(t *testing.T) {
	t.Parallel()
	assert := assert.New(t)

	key := new(eddsa.PublicKey)
	spool := NewMemSpool(key)
	message1 := []byte("hello")
	spool.Append(message1)
	message2 := []byte("goodbye")
	spool.Append(message2)

	messageID := uint32(1)
	message, _, err := spool.Get(messageID)
	assert.NoError(err)
	assert.Equal(message, message1)

	messageID = uint32(2)
	message, _, err = spool.Get(messageID)
	assert.NoError(err)
	assert.Equal(message, message2)
}

func TestMemSpoolMapBasics(t *testing.T) {
	t.Parallel()
	assert := assert.New(t)

	_, privKey, err := eddsa.Scheme().GenerateKey()
	assert.NoError(err)
	signature := privKey.Scheme().Sign(privKey, privKey.Public().(*eddsa.PublicKey).Bytes(), nil)
	assert.NoError(err)
	fileStore, err := os.CreateTemp("", "catshadow_test_filestore")
	assert.NoError(err)

	logBackend, err := log.New("", "debug", false)
	assert.NoError(err)
	logger := logBackend.GetLogger("test_logger")

	spoolMap, err := NewMemSpoolMap(fileStore.Name(), logger)
	assert.NoError(err)
	spoolID, err := spoolMap.CreateSpool(privKey.Public().(*eddsa.PublicKey), signature)
	assert.NoError(err)

	message1 := []byte("hello")
	err = spoolMap.AppendToSpool(*spoolID, message1)
	assert.NoError(err)

	messageID := uint32(1)
	message, err := spoolMap.ReadFromSpool(*spoolID, signature, messageID)
	assert.NoError(err)
	assert.Equal(message, message1)

	messageID = uint32(0)
	_, err = spoolMap.ReadFromSpool(*spoolID, signature, messageID)
	assert.Error(err)
	messageID = uint32(2)
	_, err = spoolMap.ReadFromSpool(*spoolID, signature, messageID)
	assert.Error(err)

	err = spoolMap.PurgeSpool(*spoolID, signature)
	assert.NoError(err)

	spoolMap.Shutdown()
}

func TestPersistence(t *testing.T) {
	t.Parallel()
	assert := assert.New(t)

	_, privKey, err := eddsa.Scheme().GenerateKey()
	assert.NoError(err)
	signature := privKey.Scheme().Sign(privKey, privKey.Public().(*eddsa.PublicKey).Bytes(), nil)
	fileStore, err := os.CreateTemp("", "catshadow_test_filestore")
	assert.NoError(err)

	logBackend, err := log.New("", "debug", false)
	assert.NoError(err)
	logger := logBackend.GetLogger("test_logger")

	spoolMap, err := NewMemSpoolMap(fileStore.Name(), logger)
	assert.NoError(err)
	spoolID, err := spoolMap.CreateSpool(privKey.Public().(*eddsa.PublicKey), signature)
	assert.NoError(err)
	messages := make([][]byte, 1)

	mynike := ecdh.Scheme(rand.Reader)
	nrHops := 5
	geo := geo.GeometryFromUserForwardPayloadLength(mynike, 2000, true, nrHops)

	for i := 1; i < 100; i++ {
		msg := make([]byte, common.SpoolPayloadLength(geo))
		n, err := rand.Reader.Read(msg)
		assert.NoError(err)
		assert.Equal(n, len(msg))
		messages = append(messages, msg)
		err = spoolMap.AppendToSpool(*spoolID, msg)
		assert.NoError(err)
		messageID := uint32(i)
		message, err := spoolMap.ReadFromSpool(*spoolID, signature, messageID)
		assert.NoError(err)
		assert.Equal(message, msg)
		spoolMap.Shutdown()
		spoolMap, err = NewMemSpoolMap(fileStore.Name(), logger)
		assert.NoError(err)
	}
	spoolMap.Shutdown()
}

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
	"path/filepath"
	"testing"

	"github.com/katzenpost/katzenpost/core/crypto/eddsa"
	"github.com/katzenpost/katzenpost/core/crypto/rand"
	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/memspool/common"
	"github.com/stretchr/testify/assert"
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

	privKey, err := eddsa.NewKeypair(rand.NewMath())
	assert.NoError(err)
	signature := privKey.Sign(privKey.PublicKey().Bytes())

	fileStoreName := filepath.Join(t.TempDir(), "catshadow_test_filestore")

	logBackend, err := log.New("", "debug", false)
	assert.NoError(err)
	logger := logBackend.GetLogger("test_logger")

	spoolMap, err := NewMemSpoolMap(fileStoreName, logger)
	assert.NoError(err)
	spoolID, err := spoolMap.CreateSpool(privKey.PublicKey(), signature)
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

	privKey, err := eddsa.NewKeypair(rand.NewMath())
	assert.NoError(err)
	signature := privKey.Sign(privKey.PublicKey().Bytes())
	fileStoreName := filepath.Join(t.TempDir(), "catshadow_test_filestore")
	logBackend, err := log.New("", "debug", false)
	assert.NoError(err)
	logger := logBackend.GetLogger("test_logger")

	spoolMap, err := NewMemSpoolMap(fileStoreName, logger)
	assert.NoError(err)
	spoolID, err := spoolMap.CreateSpool(privKey.PublicKey(), signature)
	assert.NoError(err)
	messages := make([][]byte, 1)
	for i := 1; i < 100; i++ {
		msg := make([]byte, common.SpoolPayloadLength)
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
		spoolMap, err = NewMemSpoolMap(fileStoreName, logger)
		assert.NoError(err)
	}
	spoolMap.Shutdown()
}

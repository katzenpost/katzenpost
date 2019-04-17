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

package main

import (
	"testing"

	"github.com/katzenpost/core/crypto/eddsa"
	"github.com/katzenpost/core/crypto/rand"
	"github.com/stretchr/testify/assert"
)

func TestSpool(t *testing.T) {
	assert := assert.New(t)

	key := new(eddsa.PublicKey)
	spool := NewMemSpool(key)
	err := spool.Append([]byte("hello"))
	assert.NoError(err)
	err = spool.Append([]byte("goodbye"))
	assert.NoError(err)

	messageID := uint32(1)
	message, err := spool.Read(messageID)
	assert.NoError(err)
	t.Logf("message: %s", message)

	messageID = uint32(2)
	message, err = spool.Read(messageID)
	assert.NoError(err)
	t.Logf("message: %s", message)
}

func TestMemSpoolMapBasics(t *testing.T) {
	assert := assert.New(t)

	privKey, err := eddsa.NewKeypair(rand.NewMath())
	assert.NoError(err)
	signature := privKey.Sign(privKey.PublicKey().Bytes())
	spoolMap := NewMemSpoolMap()
	spoolID, err := spoolMap.CreateSpool(privKey.PublicKey(), signature)
	assert.NoError(err)

	err = spoolMap.AppendToSpool(*spoolID, []byte("hello"))
	assert.NoError(err)

	messageID := uint32(1)
	message, err := spoolMap.ReadFromSpool(*spoolID, signature, messageID)
	assert.NoError(err)
	t.Logf("spooled message is %s", message)

	messageID = uint32(0)
	_, err = spoolMap.ReadFromSpool(*spoolID, signature, messageID)
	assert.Error(err)
	messageID = uint32(2)
	_, err = spoolMap.ReadFromSpool(*spoolID, signature, messageID)
	assert.Error(err)

	err = spoolMap.PurgeSpool(*spoolID, signature)
	assert.NoError(err)
}

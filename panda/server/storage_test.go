// storage_test.go - PANDA storage tests
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
	"time"

	"github.com/katzenpost/hpqc/rand"
	"github.com/katzenpost/katzenpost/panda/common"
	"github.com/stretchr/testify/assert"
)

func TestStorageBasics(t *testing.T) {
	t.Parallel()
	assert := assert.New(t)

	storeFile, err := os.CreateTemp("", "pandaStorageBasics")
	assert.NoError(err)

	dwellDuration := time.Second * 30
	writeBackInterval := time.Second * 30
	store, err := NewPandaStorage(storeFile.Name(), dwellDuration, writeBackInterval)
	assert.NoError(err)
	tag1 := &[common.PandaTagLength]byte{}
	posting1 := &PandaPosting{
		UnixTime: time.Now().Unix() - 100000,
		A:        []byte("A"),
		B:        []byte("B"),
	}
	err = store.Put(tag1, posting1)
	assert.NoError(err)

	// test that putting tag1 again causes an error
	err = store.Put(tag1, posting1)
	assert.Error(err)

	// ensure tag1dup posting is equal to the posted data
	tag1dup := &[common.PandaTagLength]byte{}
	posting2, err := store.Get(tag1dup)
	assert.NoError(err)
	assert.Equal(posting1, posting2)

	// get non-existent tag
	tag2 := &[common.PandaTagLength]byte{}
	_, err = rand.Reader.Read(tag2[:])
	assert.NoError(err)
	_, err = store.Get(tag2)
	assert.Error(err)

	// test that Replace works
	posting3 := &PandaPosting{
		UnixTime: time.Now().Unix(),
		A:        []byte("B"),
		B:        []byte("A"),
	}
	err = store.Replace(tag1, posting3)
	assert.NoError(err)
	posting4, err := store.Get(tag1)
	assert.NoError(err)
	assert.Equal(posting4, posting3)

	// test Vacuum
	assert.True(posting1.Expired(3 * time.Hour))
	assert.False(posting3.Expired(3 * time.Hour))
	err = store.Vacuum()
	assert.NoError(err)
	_, err = store.Get(tag1)
	assert.NoError(err)
	err = store.Replace(tag1, posting1)
	assert.NoError(err)
	err = store.Vacuum()
	assert.NoError(err)
	_, err = store.Get(tag1)
	assert.Error(err)

	store.Shutdown()
}

func TestStorageLoadTags(t *testing.T) {
	t.Parallel()
	assert := assert.New(t)

	storeFile, err := os.CreateTemp("", "pandaStorageLoadTags")
	assert.NoError(err)

	dwellDuration := time.Hour * 3
	writeBackInterval := time.Second * 30
	store, err := NewPandaStorage(storeFile.Name(), dwellDuration, writeBackInterval)
	assert.NoError(err)
	tag1 := &[common.PandaTagLength]byte{}
	_, err = rand.Reader.Read(tag1[:])
	assert.NoError(err)
	posting1 := &PandaPosting{
		UnixTime: time.Now().Unix(),
		A:        []byte("A"),
		B:        []byte("B"),
	}
	err = store.Put(tag1, posting1)
	assert.NoError(err)
	store.Shutdown()

	dwellDuration = time.Hour * 3
	writeBackInterval = time.Second * 30
	store, err = NewPandaStorage(storeFile.Name(), dwellDuration, writeBackInterval)
	assert.NoError(err)
	err = store.Put(tag1, posting1)
	assert.Error(err)
}

func TestStoragePurgeTags(t *testing.T) {
	t.Parallel()
	assert := assert.New(t)

	storeFile, err := os.CreateTemp("", "pandaStoragePurgeTags")
	assert.NoError(err)

	dwellDuration := time.Second * 30
	writeBackInterval := time.Second * 30
	store, err := NewPandaStorage(storeFile.Name(), dwellDuration, writeBackInterval)
	assert.NoError(err)
	tag1 := &[common.PandaTagLength]byte{}
	_, err = rand.Reader.Read(tag1[:])
	assert.NoError(err)
	posting1 := &PandaPosting{
		UnixTime: time.Now().Unix(),
		A:        []byte("A"),
		B:        []byte("B"),
	}
	err = store.Put(tag1, posting1)
	assert.NoError(err)
	for i := 0; i < 10; i++ {
		t := &[common.PandaTagLength]byte{}
		_, err = rand.Reader.Read(t[:])
		assert.NoError(err)
		p := &PandaPosting{
			UnixTime: time.Now().Unix(),
			A:        []byte("A"),
			B:        []byte("B"),
		}
		err = store.Put(t, p)
		assert.NoError(err)
	}
	store.Shutdown()

	dwellDuration = time.Second * 30
	writeBackInterval = time.Second * 30
	store, err = NewPandaStorage(storeFile.Name(), dwellDuration, writeBackInterval)
	assert.NoError(err)
	err = store.Put(tag1, posting1)
	assert.Error(err)
	store.postings.Delete(*tag1)
	store.Shutdown()

	dwellDuration = time.Second * 30
	writeBackInterval = time.Second * 30
	store, err = NewPandaStorage(storeFile.Name(), dwellDuration, writeBackInterval)
	assert.NoError(err)
	err = store.Put(tag1, posting1)
	assert.NoError(err)
}

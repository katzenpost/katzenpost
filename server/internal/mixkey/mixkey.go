// mixkey.go - Mix keys and associated utilities.
// Copyright (C) 2017  Yawning Angel.
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

// Package mixkey provides persistent mix keys and associated utilities.
package mixkey

import (
	"crypto/sha512"
	"sync"
	"sync/atomic"

	"github.com/yawning/bloom"
	bolt "go.etcd.io/bbolt"

	"github.com/katzenpost/hpqc/kem"
	"github.com/katzenpost/hpqc/nike"
	"github.com/katzenpost/hpqc/rand"

	"github.com/katzenpost/katzenpost/core/sphinx/geo"
)

const (
	// TagLength is the replay tag length in bytes.
	TagLength = sha512.Size256
)

var dbOptions = &bolt.Options{
	NoFreelistSync: true,
}

// MixKey is a Katzenpost server mix key.
type MixKey struct {
	sync.Mutex

	nikeKeypair nike.PrivateKey
	nikePubKey  nike.PublicKey
	kemKeypair  kem.PrivateKey
	epoch       uint64

	f *bloom.Filter

	refCount        int32
	unlinkIfExpired bool
}

// SetUnlinkIfExpired sets if the key will be deleted when closed if it is
// expired.
func (k *MixKey) SetUnlinkIfExpired(b bool) {
	k.unlinkIfExpired = b
}

// PublicKey returns the public component of the key.
func (k *MixKey) PublicKey() (nike.PublicKey, kem.PublicKey) {
	if k.nikePubKey == nil {
		return nil, k.kemKeypair.Public()
	} else {
		return k.nikePubKey, nil
	}
}

// PublicBytes returns the public key in raw bytes.
func (k *MixKey) PublicBytes() []byte {
	if k.nikePubKey == nil {
		blob, err := k.kemKeypair.Public().MarshalBinary()
		if err != nil {
			panic(err)
		}
		return blob
	} else {
		return k.nikePubKey.Bytes()
	}
}

// PrivateKey returns the private component of the key.
func (k *MixKey) PrivateKey() interface{} {
	if k.nikeKeypair == nil {
		return k.kemKeypair
	} else {
		return k.nikeKeypair
	}
}

// Epoch returns the Katzenpost epoch associated with the keypair.
func (k *MixKey) Epoch() uint64 {
	return k.epoch
}

// IsReplay marks a given replay tag as seen, and returns true iff the tag has
// been seen previously (Test and Set).
func (k *MixKey) IsReplay(rawTag []byte) bool {
	// Treat all pathologically malformed tags as replays.
	if len(rawTag) != TagLength {
		return true
	}
	var tag [TagLength]byte
	copy(tag[:], rawTag)

	k.Lock()
	defer k.Unlock()

	// If the filter is saturated then probability of a false replay is increased
	// XXX: the filter size should be tuned for the maximum line rate expected so that this does not happen
	if k.f.Entries() >= k.f.MaxEntries() {
		panic("MixKey bloom filter size too small")
	}
	if !k.f.TestAndSet(tag[:]) {
		return false
	}
	return true
}

// Deref reduces the refcount by one, and closes the key if the refcount hits
// 0.
func (k *MixKey) Deref() {
	i := atomic.AddInt32(&k.refCount, -1)
	if i == 0 {
		k.forceClose()
	} else if i < 0 {
		panic("BUG: mixkey: Refcount is negative")
	}
}

// Ref increases the refcount by one.
func (k *MixKey) Ref() {
	i := atomic.AddInt32(&k.refCount, 1)
	if i <= 1 {
		panic("BUG: mixkey: Refcount was 0 or negative")
	}
}

func (k *MixKey) forceClose() {
	if k.nikeKeypair != nil {
		k.nikeKeypair.Reset()
		k.nikePubKey.Reset()
	}

	if k.kemKeypair != nil {
		// k.kemKeypair.Reset()
		k.kemKeypair = nil
	}
}

// New creates (or loads) a mix key in the provided data directory, for the
// given epoch.
func New(epoch uint64, g *geo.Geometry) (*MixKey, error) {
	var err error

	// Initialize the structure and create or open the database.
	k := &MixKey{
		epoch:    epoch,
		refCount: 1,
	}

	k.f, err = bloom.New(rand.Reader, 29, 0.001) // 64 MiB, 37,240,820 entries.
	if err != nil {
		return nil, err
	}

	nikeScheme, kemScheme := g.Scheme()
	if nikeScheme != nil {
		k.nikePubKey, k.nikeKeypair, err = nikeScheme.GenerateKeyPair()
		if err != nil {
			return nil, err
		}
	} else {
		_, k.kemKeypair, err = kemScheme.GenerateKeyPair()
		if err != nil {
			return nil, err
		}
	}

	return k, nil
}

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
	"errors"
	"fmt"
	"os"
	"path/filepath"
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

	// keyFileMagic identifies persisted mix key files.
	keyFileMagic = "KMK1"

	// keyFileKindNike and keyFileKindKem identify the private key kind a
	// persisted mix key file contains.
	keyFileKindNike = 0
	keyFileKindKem  = 1
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
	k, err := newKey(epoch, g)
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

// Load returns the mix key persisted for the given epoch, if any. The bool
// reports whether a key was found and loaded; a nil error with a false bool
// means no key file exists (the caller should generate a fresh key). Any
// other error means a key file exists but could not be loaded, because it is
// corrupt or was written for a different scheme; the caller should log it and
// fall back to generating a fresh key.
func Load(epoch uint64, g *geo.Geometry, keyStoreDir string) (*MixKey, bool, error) {
	blob, err := os.ReadFile(keyPath(epoch, keyStoreDir))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, false, nil
		}
		return nil, false, err
	}

	// Layout: magic, key kind, private key material.
	if len(blob) < len(keyFileMagic)+1 {
		return nil, false, fmt.Errorf("mixkey: persisted key file for epoch %d is truncated", epoch)
	}
	if string(blob[:len(keyFileMagic)]) != keyFileMagic {
		return nil, false, fmt.Errorf("mixkey: persisted key file for epoch %d has an invalid header", epoch)
	}
	kind := blob[len(keyFileMagic)]
	keyBytes := blob[len(keyFileMagic)+1:]

	k, err := newKey(epoch, g)
	if err != nil {
		return nil, false, err
	}

	nikeScheme, kemScheme := g.Scheme()
	switch {
	case nikeScheme != nil && kind == keyFileKindNike:
		k.nikeKeypair, err = nikeScheme.UnmarshalBinaryPrivateKey(keyBytes)
		if err != nil {
			return nil, false, fmt.Errorf("mixkey: failed to load nike key for epoch %d: %v", epoch, err)
		}
		k.nikePubKey = k.nikeKeypair.Public()
	case kemScheme != nil && kind == keyFileKindKem:
		k.kemKeypair, err = kemScheme.UnmarshalBinaryPrivateKey(keyBytes)
		if err != nil {
			return nil, false, fmt.Errorf("mixkey: failed to load kem key for epoch %d: %v", epoch, err)
		}
	default:
		return nil, false, fmt.Errorf("mixkey: persisted key file for epoch %d was written for a different scheme", epoch)
	}

	return k, true, nil
}

// Persist writes the private key material to the key store directory, keyed
// by the key's epoch. It is used on clean shutdown so that a subsequent boot
// can reload the same keypair and remain in sync with the already-published
// consensus. The write is atomic (temp file + rename).
func (k *MixKey) Persist(keyStoreDir string) error {
	kind := byte(keyFileKindNike)
	var keyBytes []byte
	switch {
	case k.nikeKeypair != nil:
		keyBytes = k.nikeKeypair.Bytes()
	case k.kemKeypair != nil:
		kind = keyFileKindKem
		var err error
		keyBytes, err = k.kemKeypair.MarshalBinary()
		if err != nil {
			return err
		}
	default:
		return errors.New("mixkey: cannot persist a key with no private key material")
	}

	blob := make([]byte, 0, len(keyFileMagic)+1+len(keyBytes))
	blob = append(blob, keyFileMagic...)
	blob = append(blob, kind)
	blob = append(blob, keyBytes...)

	if err := os.MkdirAll(keyStoreDir, 0700); err != nil {
		return err
	}
	return atomicWrite(keyPath(k.epoch, keyStoreDir), blob)
}

// Remove deletes the persisted key file for the given epoch, if present.
func Remove(epoch uint64, keyStoreDir string) {
	os.Remove(keyPath(epoch, keyStoreDir))
}

func keyPath(epoch uint64, keyStoreDir string) string {
	return filepath.Join(keyStoreDir, fmt.Sprintf("mixkey-%d.bin", epoch))
}

func atomicWrite(path string, blob []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".mixkey-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)

	if _, err := tmp.Write(blob); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}

func newKey(epoch uint64, g *geo.Geometry) (*MixKey, error) {
	k := &MixKey{
		epoch:    epoch,
		refCount: 1,
	}

	f, err := bloom.New(rand.Reader, 29, 0.001) // 64 MiB, 37,240,820 entries.
	if err != nil {
		return nil, err
	}
	k.f = f
	return k, nil
}

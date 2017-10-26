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
	"encoding/binary"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"git.schwanenlied.me/yawning/bloom.git"
	bolt "github.com/coreos/bbolt"
	"github.com/katzenpost/core/crypto/ecdh"
	"github.com/katzenpost/core/crypto/rand"
	"github.com/katzenpost/core/epochtime"
)

const (
	replayBucket   = "replay"
	metadataBucket = "metadata"

	writeBackInterval = 10 * time.Second
	writeBackSize     = 4096 // TODO/perf: Tune this.

	// TagLength is the replay tag length in bytes.
	TagLength = sha512.Size256
)

// MixKey is a Katzenpost server mix key.
type MixKey struct {
	sync.Mutex
	sync.WaitGroup

	db      *bolt.DB
	keypair *ecdh.PrivateKey
	epoch   uint64

	f         *bloom.Filter
	writeBack map[[TagLength]byte]bool
	flushCh   chan interface{}
	haltCh    chan interface{}

	refCount        int32
	unlinkIfExpired bool
}

// SetUnlinkIfExpired sets if the key will be deleted when closed if it is
// expired.
func (k *MixKey) SetUnlinkIfExpired(b bool) {
	k.unlinkIfExpired = b
}

// PublicKey returns the public component of the key.
func (k *MixKey) PublicKey() *ecdh.PublicKey {
	return k.keypair.PublicKey()
}

// PrivateKey returns the private component of the key.
func (k *MixKey) PrivateKey() *ecdh.PrivateKey {
	return k.keypair
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

	// Check the bloom filter for the tag, to see if it might be a replay.
	maybeReplay, inWriteBack := k.testAndSetTagMemory(&tag)
	if !maybeReplay {
		// k.isNotReplay() will add the tag to the write-back cache, so
		// just poke the flush routine and return.
		select {
		case k.flushCh <- true:
		default:
			// Non-blocking channel write, because the channel is buffered
			// and has a timer fallback.
		}
		return false
	}

	// Slow path, either a false positive or a replay.
	//
	// Note: It alternatively would be acceptable to just drop the packet,
	// but k.isNotReplay()'s behavior will need to change on filter
	// saturation.

	isReplay := inWriteBack
	if !isReplay {
		// Well, it's not in the write-back cache, so query the database.
		//
		// Since we're stuck hitting the database anyway, might as well
		// bypass the cache and save ourselves some pain by doing the
		// insertion here.
		if err := k.db.Update(func(tx *bolt.Tx) error {
			bkt := tx.Bucket([]byte(replayBucket))
			isReplay = testAndSetTagDB(bkt, tag[:])
			return nil
		}); err != nil {
			panic("BUG: mixkey: Failed to query the replay filter: " + err.Error())
		}
	}
	return isReplay
}

func testAndSetTagDB(bkt *bolt.Bucket, tag []byte) bool {
	// Retreive the counter from the database for the tag if it exists.
	//
	// XXX: The counter isn't actually used for anything since it isn't
	// returned.  Not sure if it makes sense to keep it, but I don't think
	// it costs us anything substantial to do so.
	var seenCount uint64
	if b := bkt.Get(tag); b != nil {
		if len(b) == 8 {
			seenCount = binary.LittleEndian.Uint64(b)
		} else {
			// Treat invalid but present entries as being seen.
			seenCount = 1
		}
	}
	seenCount++         // Increment the counter by 1.
	if seenCount == 0 { // Should never happen ever, but handle correctly.
		seenCount = math.MaxUint64
	}

	// Write the (potentially incremented) counter.
	var seenBytes [8]byte
	binary.LittleEndian.PutUint64(seenBytes[:], seenCount)
	bkt.Put(tag, seenBytes[:])
	return seenCount != 1
}

func (k *MixKey) testAndSetTagMemory(tag *[TagLength]byte) (bool, bool) {
	k.Lock()
	defer k.Unlock()

	// TODO/perf: Perhaps the lock should only cover the bloom filter,
	// and a sync.Map used for the pending write-back entries.

	// If the filter is saturated then force a database lookup.
	if k.f.Entries() >= k.f.MaxEntries() {
		return true, k.writeBack[*tag]
	}
	if !k.f.TestAndSet(tag[:]) {
		// The tag is not in the bloom filter, so by definition it is not a replay.

		// Insert it into the write-back cache.
		k.writeBack[*tag] = true
		return false, true
	}

	// Do the write-back cache lookup while we hold the lock.
	return true, k.writeBack[*tag]
}

func (k *MixKey) worker() {
	defer func() {
		k.doFlush(true)
		k.Done()
	}()

	ticker := time.NewTicker(writeBackInterval)
	defer ticker.Stop()

	for {
		forceFlush := false
		select {
		case <-k.haltCh:
			return
		case <-k.flushCh:
		case <-ticker.C:
			forceFlush = true
		}
		k.doFlush(forceFlush)
	}
}

func (k *MixKey) doFlush(forceFlush bool) {
	k.Lock()
	defer k.Unlock()

	// Accumulate up to writeBackSize entries.
	nEntries := len(k.writeBack)
	if nEntries == 0 || (!forceFlush && nEntries < writeBackSize) {
		return
	}

	if err := k.db.Update(func(tx *bolt.Tx) error {
		bkt := tx.Bucket([]byte(replayBucket))
		for tag := range k.writeBack {
			testAndSetTagDB(bkt, tag[:])
		}
		return nil
	}); err != nil {
		panic("BUG: mixkey: Failed to flush write-back cache: " + err.Error())
	}
	k.writeBack = make(map[[TagLength]byte]bool)
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
	if k.db != nil {
		f := k.db.Path() // Cache so we can unlink after Close().

		// Gracefully terminate the worker.
		close(k.haltCh)
		k.Wait()

		// Force the DB to disk, and close.
		k.db.Sync()
		k.db.Close()
		k.db = nil

		// Delete the database if the key is expired, and the owner requested
		// full cleanup.
		epoch, _, _ := epochtime.Now()
		if k.unlinkIfExpired && k.epoch < epoch-1 {
			// People will probably complain that this doesn't attempt
			// "secure" deletion, but that's fundementally a lost cause
			// given how many levels of indirection there are to files vs
			// the raw physical media, and the cleanup process being slightly
			// race prone around epoch transitions.  Use FDE.
			os.Remove(f)
		}
	}
	if k.keypair != nil {
		k.keypair.Reset()
		k.keypair = nil
	}
}

// New creates (or loads) a mix key in the provided data directory, for the
// given epoch.
func New(dataDir string, epoch uint64) (*MixKey, error) {
	const (
		versionKey = "version"
		pkKey      = "privateKey"
		epochKey   = "epochKey"
	)
	var err error

	// Initialize the structure and create or open the database.
	f := filepath.Join(dataDir, fmt.Sprintf("mixkey-%d.db", epoch))
	k := new(MixKey)
	k.epoch = epoch
	k.refCount = 1
	k.db, err = bolt.Open(f, 0600, nil) // TODO: O_DIRECT?
	if err != nil {
		return nil, err
	}
	k.f, err = bloom.New(rand.Reader, 29, 0.001) // 64 MiB, 37,240,820 entries.
	if err != nil {
		return nil, err
	}
	k.writeBack = make(map[[TagLength]byte]bool)
	k.flushCh = make(chan interface{}, 1)
	k.haltCh = make(chan interface{})

	didCreate := false
	if err := k.db.Update(func(tx *bolt.Tx) error {
		// Ensure that all the buckets exist.
		bkt, err := tx.CreateBucketIfNotExists([]byte(metadataBucket))
		if err != nil {
			return err
		}
		replayBkt, err := tx.CreateBucketIfNotExists([]byte(replayBucket))
		if err != nil {
			return err
		}

		if b := bkt.Get([]byte(versionKey)); b != nil {
			// Well, looks like we loaded as opposed to created.
			if len(b) != 1 || b[0] != 0 {
				return fmt.Errorf("mixkey: incompatible version: %d", uint(b[0]))
			}

			// Deserialize the key.
			if b = bkt.Get([]byte(pkKey)); b == nil {
				return fmt.Errorf("mixkey: db missing privateKey entry")
			}
			k.keypair = new(ecdh.PrivateKey)
			if err = k.keypair.FromBytes(b); err != nil {
				return err
			}

			getUint64 := func(key string) (uint64, error) {
				var buf []byte
				if buf = bkt.Get([]byte(key)); buf == nil {
					return 0, fmt.Errorf("mixkey: db missing entry '%v'", key)
				}
				if len(buf) != 8 {
					return 0, fmt.Errorf("mixkey: db corrupted entry '%v'", key)
				}
				return binary.LittleEndian.Uint64(buf), nil
			}

			// Ensure the epoch is sane.
			var dbEpoch uint64
			dbEpoch, err = getUint64(epochKey)
			if err != nil {
				return err
			} else if dbEpoch != epoch {
				return fmt.Errorf("mixkey: db epoch mismatch")
			}

			// Rebuild the bloom filter.
			replayBkt.ForEach(func(tag, rawCount []byte) error {
				k.f.TestAndSet(tag)
				return nil
			})

			return nil
		}

		// If control reaches here, then a new key needs to be created.
		didCreate = true
		k.keypair, err = ecdh.NewKeypair(rand.Reader)
		if err != nil {
			return err
		}
		var epochBytes [8]byte
		binary.LittleEndian.PutUint64(epochBytes[:], epoch)

		// Stash the version/key/epoch in the metadata bucket.
		bkt.Put([]byte(versionKey), []byte{0})
		bkt.Put([]byte(pkKey), k.keypair.Bytes())
		bkt.Put([]byte(epochKey), epochBytes[:])

		return nil
	}); err != nil {
		k.db.Close()
		return nil, err
	}
	if didCreate {
		// Flush the newly created database to disk.
		k.db.Sync()
	}

	k.Add(1)
	go k.worker()

	return k, nil
}

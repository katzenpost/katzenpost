// boltuserdb.go - BoltDB backed Katzenpost server user database.
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

// Package boltuserdb implements the Katzenpost server user database with a
// simple boltdb based backend.
package boltuserdb

import (
	"crypto/subtle"
	"fmt"
	"sync"

	bolt "github.com/coreos/bbolt"
	"github.com/katzenpost/core/crypto/ecdh"
	"github.com/katzenpost/server/userdb"
)

const usersBucket = "users"

type boltUserDB struct {
	sync.RWMutex

	db        *bolt.DB
	userCache map[[userdb.MaxUsernameSize]byte]bool
}

func (d *boltUserDB) Exists(u []byte) bool {
	// Reject pathologically malformed usernames.
	if len(u) == 0 || len(u) > userdb.MaxUsernameSize {
		return false
	}

	k := userToCacheKey(u)

	d.RLock()
	defer d.RUnlock()

	return d.userCache[k]
}

func (d *boltUserDB) IsValid(u []byte, k *ecdh.PublicKey) bool {
	// Reject pathologically malformed arguments.
	if len(u) == 0 || len(u) > userdb.MaxUsernameSize || k == nil {
		return false
	}

	// Query the database to see if the user is present, and if the public
	// keys match.
	isValid := false
	if err := d.db.View(func(tx *bolt.Tx) error {
		// Grab the `users` bucket.
		bkt := tx.Bucket([]byte(usersBucket))

		// If the user exists in the `users` bucket, then compare public keys.
		rawPubKey := bkt.Get(u)
		if rawPubKey != nil {
			isValid = subtle.ConstantTimeCompare(rawPubKey, k.Bytes()) == 1
		}
		return nil
	}); err != nil {
		return false
	}
	return isValid
}

func (d *boltUserDB) Add(u []byte, k *ecdh.PublicKey, update bool) error {
	if len(u) == 0 || len(u) > userdb.MaxUsernameSize {
		return fmt.Errorf("userdb: invalid username: `%v`", u)
	}
	if k == nil {
		return fmt.Errorf("userdb: must provide a public key")
	}
	if d.Exists(u) && !update {
		return fmt.Errorf("userdb: user already exists")
	}

	err := d.db.Update(func(tx *bolt.Tx) error {
		// Grab the `users` bucket.
		bkt := tx.Bucket([]byte(usersBucket))

		// And add or update the user's entry.
		return bkt.Put(u, k.Bytes())
	})
	if err == nil {
		k := userToCacheKey(u)

		d.Lock()
		defer d.Unlock()

		d.userCache[k] = true
	}

	return err
}

func (d *boltUserDB) Remove(u []byte) error {
	if len(u) == 0 || len(u) > userdb.MaxUsernameSize {
		return fmt.Errorf("userdb: invalid username: `%v`", u)
	}

	err := d.db.Update(func(tx *bolt.Tx) error {
		// Grab the `users` bucket.
		bkt := tx.Bucket([]byte(usersBucket))

		// Delete the user's entry.
		return bkt.Delete(u)
	})
	if err == nil {
		k := userToCacheKey(u)

		d.Lock()
		defer d.Unlock()

		delete(d.userCache, k)
	}
	return err
}

func (d *boltUserDB) Close() {
	d.db.Sync()
	d.db.Close()
}

// New creates (or loads) a user database with the given file name f.
func New(f string) (userdb.UserDB, error) {
	const (
		metadataBucket = "metadata"
		versionKey     = "version"
	)

	var err error

	d := new(boltUserDB)
	d.db, err = bolt.Open(f, 0600, nil)
	if err != nil {
		return nil, err
	}
	d.userCache = make(map[[userdb.MaxUsernameSize]byte]bool)

	if err = d.db.Update(func(tx *bolt.Tx) error {
		// Ensure that all the buckets exists, and grab the metadata bucket.
		bkt, err := tx.CreateBucketIfNotExists([]byte(metadataBucket))
		if err != nil {
			return err
		}
		if _, err = tx.CreateBucketIfNotExists([]byte(usersBucket)); err != nil {
			return err
		}

		if b := bkt.Get([]byte(versionKey)); b != nil {
			// Well it looks like we loaded as opposed to created.
			if len(b) != 1 || b[0] != 0 {
				return fmt.Errorf("userdb: incompatible version: %d", uint(b[0]))
			}

			// Populate the user cache.
			bkt = tx.Bucket([]byte(usersBucket))
			bkt.ForEach(func(k, v []byte) error {
				u := userToCacheKey(k)
				d.userCache[u] = true
				return nil
			})

			return nil
		}

		// We created a new database, so populate the new `metadata` bucket.
		bkt.Put([]byte(versionKey), []byte{0})

		return nil
	}); err != nil {
		// The struct isn't getting returned so clean up the database.
		d.db.Close()
		return nil, err
	}

	return d, nil
}

func userToCacheKey(u []byte) [userdb.MaxUsernameSize]byte {
	var k [userdb.MaxUsernameSize]byte
	copy(k[:], u)
	return k
}

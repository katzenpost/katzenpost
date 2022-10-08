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
	"errors"
	"fmt"
	"sync"

	"github.com/katzenpost/katzenpost/core/wire"
	"github.com/katzenpost/katzenpost/server/userdb"
	bolt "go.etcd.io/bbolt"
)

const (
	usersBucket      = "users"
	identitiesBucket = "identities"
)

type BoltUserDBOption func(*boltUserDB)

func WithTrustOnFirstUse() BoltUserDBOption {
	return func(db *boltUserDB) {
		db.trustOnFirstUse = true
	}
}

type boltUserDB struct {
	sync.RWMutex

	db        *bolt.DB
	userCache map[[userdb.MaxUsernameSize]byte]bool

	trustOnFirstUse bool

	scheme wire.Scheme
}

func (d *boltUserDB) Exists(u []byte) bool {
	if !userOk(u) {
		return false
	}

	k := userToCacheKey(u)

	d.RLock()
	defer d.RUnlock()

	return d.userCache[k]
}

func (d *boltUserDB) IsValid(u []byte, k wire.PublicKey) bool {
	if !userOk(u) {
		return false
	}

	// Query the database to see if the user is present, and if the public
	// keys match.
	isValid := false
	tofuUser := false
	if err := d.db.View(func(tx *bolt.Tx) error {
		bkt := tx.Bucket([]byte(usersBucket))

		// If the user exists in the `users` bucket, then compare public keys.
		rawPubKey := bkt.Get(u)
		if rawPubKey == nil {
			if d.trustOnFirstUse == true {
				tofuUser = true
			} else {
				return errors.New("user does not exist")
			}
		} else {
			isValid = subtle.ConstantTimeCompare(rawPubKey, k.Bytes()) == 1
			if isValid {
				return nil
			} else {
				return errors.New("public keys don't match")
			}
		}
		return nil
	}); err != nil {
		return false
	}
	if tofuUser {
		if err := d.Add(u, k, false); err != nil {
			return false
		}
	}
	return true
}

func (d *boltUserDB) Add(u []byte, k wire.PublicKey, update bool) error {
	if !userOk(u) {
		return fmt.Errorf("userdb: invalid username: `%v`", u)
	}
	if k == nil {
		return fmt.Errorf("userdb: must provide a public key")
	}
	switch d.Exists(u) {
	case true:
		if !update {
			return fmt.Errorf("userdb: user already exists")
		}
	case false:
		if update {
			return userdb.ErrNoSuchUser
		}
	}

	err := d.db.Update(func(tx *bolt.Tx) error {
		bkt := tx.Bucket([]byte(usersBucket))
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

func (d *boltUserDB) SetIdentity(u []byte, k wire.PublicKey) error {
	if !userOk(u) {
		return fmt.Errorf("userdb: invalid username: `%v`", u)
	}

	return d.db.Update(func(tx *bolt.Tx) error {
		uBkt := tx.Bucket([]byte(usersBucket))
		if uEnt := uBkt.Get(u); uEnt == nil {
			return userdb.ErrNoSuchUser
		}

		iBkt := tx.Bucket([]byte(identitiesBucket))
		if k == nil {
			return iBkt.Delete(u)
		}
		return iBkt.Put(u, k.Bytes())
	})
}

func (d *boltUserDB) Link(u []byte) (wire.PublicKey, error) {
	if !userOk(u) {
		return nil, fmt.Errorf("userdb: invalid username: `%v`", u)
	}
	if !d.Exists(u) {
		return nil, fmt.Errorf("userdb: user does not exist")
	}

	var pubKey wire.PublicKey
	err := d.db.View(func(tx *bolt.Tx) error {
		bkt := tx.Bucket([]byte(usersBucket))
		rawPubKey := bkt.Get(u)
		if rawPubKey == nil {
			return fmt.Errorf("userdb: user %s does not have a link key", u)
		}
		var err error
		pubKey, err = d.scheme.UnmarshalTextPublicKey(rawPubKey)
		return err
	})
	return pubKey, err
}

func (d *boltUserDB) Identity(u []byte) (wire.PublicKey, error) {
	if !userOk(u) {
		return nil, fmt.Errorf("userdb: invalid username: `%v`", u)
	}

	var pubKey wire.PublicKey
	err := d.db.View(func(tx *bolt.Tx) error {
		uBkt := tx.Bucket([]byte(usersBucket))
		if uEnt := uBkt.Get(u); uEnt == nil {
			return userdb.ErrNoSuchUser
		}

		iBkt := tx.Bucket([]byte(identitiesBucket))
		rawPubKey := iBkt.Get(u)
		if rawPubKey == nil {
			return userdb.ErrNoIdentity
		}

		var err error
		pubKey, err = d.scheme.UnmarshalTextPublicKey(rawPubKey)
		return err
	})

	return pubKey, err
}

func (d *boltUserDB) Remove(u []byte) error {
	if !userOk(u) {
		return fmt.Errorf("userdb: invalid username: `%v`", u)
	}

	err := d.db.Update(func(tx *bolt.Tx) error {
		bkt := tx.Bucket([]byte(usersBucket))

		// Delete the user's entry iff it exists.
		if ent := bkt.Get(u); ent == nil {
			return userdb.ErrNoSuchUser
		}
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
func New(f string, opts ...BoltUserDBOption) (userdb.UserDB, error) {
	const (
		metadataBucket = "metadata"
		versionKey     = "version"
	)

	var err error

	d := new(boltUserDB)

	for _, opt := range opts {
		opt(d)
	}

	d.scheme = wire.DefaultScheme
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
		uBkt, err := tx.CreateBucketIfNotExists([]byte(usersBucket))
		if err != nil {
			return err
		}
		if _, err = tx.CreateBucketIfNotExists([]byte(identitiesBucket)); err != nil {
			return err
		}

		if b := bkt.Get([]byte(versionKey)); b != nil {
			// Well it looks like we loaded as opposed to created.
			if len(b) != 1 || b[0] != 0 {
				return fmt.Errorf("userdb: incompatible version: %d", uint(b[0]))
			}

			// Populate the user cache.
			uBkt.ForEach(func(k, v []byte) error {
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

func userOk(u []byte) bool {
	return len(u) > 0 || len(u) <= userdb.MaxUsernameSize
}

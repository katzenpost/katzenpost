// boltspool.go - BoltDB backed Katzenpost server user message spool
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

// Package boltspool implements the Katzenpost server user message spool with
// a simple boltdb based backend.
package boltspool

import (
	"encoding/binary"
	"fmt"

	bolt "github.com/coreos/bbolt"
	"github.com/katzenpost/core/constants"
	sConstants "github.com/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/server/spool"
	"github.com/katzenpost/server/userdb"
)

const (
	usersBucket = "users"
	msgKey      = "message"
	surbIDKey   = "surbID"
)

type boltSpool struct {
	db *bolt.DB
}

func (s *boltSpool) Close() {
	s.db.Sync()
	s.db.Close()
}

func (s *boltSpool) StoreMessage(u, msg []byte) error {
	if len(msg) != constants.UserForwardPayloadLength {
		return fmt.Errorf("spool: invalid user message size: %d", len(msg))
	}
	return s.doStore(u, nil, msg)
}

func (s *boltSpool) StoreSURBReply(u []byte, id *[sConstants.SURBIDLength]byte, msg []byte) error {
	if len(msg) != constants.ForwardPayloadLength {
		return fmt.Errorf("spool: invalid SURBReply message size: %d", len(msg))
	}
	if id == nil {
		return fmt.Errorf("spool: SURBReply is missing ID")
	}

	return s.doStore(u, id, msg)
}

func (s *boltSpool) doStore(u []byte, id *[sConstants.SURBIDLength]byte, msg []byte) error {
	if len(u) == 0 || len(u) > userdb.MaxUsernameSize {
		return fmt.Errorf("spool: invalid username: `%v`", u)
	}

	return s.db.Update(func(tx *bolt.Tx) error {
		// Grab the `users` bucket.
		uBkt := tx.Bucket([]byte(usersBucket))

		// Grab or create the user's spool bucket.
		sBkt, err := uBkt.CreateBucketIfNotExists(u)
		if err != nil {
			return err
		}

		// Allocate a unique identifier for this message.
		seq, err := sBkt.NextSequence()
		if err != nil {
			return err
		}
		var msgID [8]byte
		binary.BigEndian.PutUint64(msgID[:], seq)

		// Create a bucket for this message.
		mBkt, err := sBkt.CreateBucket(msgID[:])
		if err != nil {
			return err
		}

		// Store the message and (optional) SURB ID.
		mBkt.Put([]byte(msgKey), msg)
		if id != nil {
			mBkt.Put([]byte(surbIDKey), id[:])
		}
		return nil
	})
}

func (s *boltSpool) Get(u []byte, advance bool) (msg, surbID []byte, remaining int, err error) {
	// This uses manual transaction management because there is a trivial
	// amount of extra work for the `advance == true` case that requires
	// a writeable transaction.
	//
	// Doing it this way avoids a considrable amount of code duplication,
	// and the common case is likely that the user's spool is empty, which
	// doesn't require updating the database at all (concurrency).

	var tx *bolt.Tx
	tx, err = s.db.Begin(advance)
	if err != nil {
		return
	}
	defer tx.Rollback()

	// Grab the `users` bucket.
	uBkt := tx.Bucket([]byte(usersBucket))

	// Grab the user's spool bucket.
	sBkt := uBkt.Bucket(u)
	if sBkt == nil {
		// If the user's spool bucket is missing, the spool is empty.
		return
	}

	// Grab a cursor into the user's spool.
	cur := sBkt.Cursor()
	mKey, _ := cur.First()
	if mKey == nil {
		// If the user's spool bucket is empty, the spool is empty.
		return
	}

	// Well, there has to be at least one message in the spool, and this
	// is merely a hint, so just return 0 if the queue is empty or there
	// is only one message, and 1 if there are any number of messages.
	remaining = 1
	next, _ := cur.Next()

	if advance {
		// Delete the 0th message.
		if err = sBkt.DeleteBucket(mKey); err != nil {
			return
		}

		if next == nil {
			// Deleting the message drained the queue.
			sBkt.SetSequence(0) // Don't keep a lifetime message count.
			remaining = 0
			err = tx.Commit()
			return
		}
		mKey = next
		next, _ = cur.Next()
	}

	if next == nil {
		// "excluding the current message".
		remaining = 0
	}

	// Retreive the stored message and (optional) SURB ID.
	mBkt := sBkt.Bucket(mKey)
	msg = mBkt.Get([]byte(msgKey))
	surbID = mBkt.Get([]byte(surbIDKey))

	// If we modified the database, commit the transaction.
	if advance {
		err = tx.Commit()
	}
	return
}

func (s *boltSpool) Remove(u []byte) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		// Grab the `users` bucket.
		uBkt := tx.Bucket([]byte(usersBucket))

		// Grab the user's spool bucket.
		sBkt := uBkt.Bucket(u)
		if sBkt == nil {
			// If the user's spool bucket is missing, just return.
			return nil
		}

		return uBkt.DeleteBucket(u)
	})
}

func (s *boltSpool) Vaccum(udb userdb.UserDB) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		// Grab the `users` bucket.
		uBkt := tx.Bucket([]byte(usersBucket))

		cur := uBkt.Cursor()
		for u, _ := cur.First(); u != nil; u, _ = cur.Next() {
			// Note: If the provided UserDB doesn't do something intelligent
			// like cache the valid users, this will really suck.
			if udb.Exists(u) {
				continue
			}
			if err := uBkt.DeleteBucket(u); err != nil {
				return err
			}
		}
		return nil
	})
}

// New creates (or loads) a user message spool with the given file name f.
func New(f string) (spool.Spool, error) {
	const (
		metadataBucket = "metadata"
		versionKey     = "version"
	)

	var err error

	s := new(boltSpool)
	s.db, err = bolt.Open(f, 0600, nil)
	if err != nil {
		return nil, err
	}

	if err = s.db.Update(func(tx *bolt.Tx) error {
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
				return fmt.Errorf("spool: incompatible version: %d", uint(b[0]))
			}
			return nil
		}

		// We created a new database, so populate the new `metadata` bucket.
		bkt.Put([]byte(versionKey), []byte{0})

		return nil
	}); err != nil {
		// The struct isn't getting returned so clean up the database.
		s.db.Close()
		return nil, err
	}

	return s, nil
}

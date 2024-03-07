// userdb.go - Katzenpost server user database interface.
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

// Package userdb defines the Katzenpost server user database abstract
// interface.
package userdb

import (
	"errors"

	"github.com/katzenpost/hpqc/kem"

	"github.com/katzenpost/katzenpost/core/sphinx/constants"
)

// MaxUsernameSize is the maximum username length in bytes.
const MaxUsernameSize = constants.RecipientIDLength

var (
	// ErrNoSuchUser is the error returned when an operation fails due to
	// a non-existent user.
	ErrNoSuchUser = errors.New("userdb: no such user")

	// ErrNoIdentity is the error returned when the specified user has no
	// identity key set.
	ErrNoIdentity = errors.New("userdb: no identity key set")
)

// UserDB is the interface provided by all user database implementations.
type UserDB interface {
	// Exists returns true iff the user identified by the username exists.
	Exists([]byte) bool

	// IsValid returns true iff the user identified by the username and
	// public key is valid.
	IsValid([]byte, kem.PublicKey) bool

	// Link returns the user's link layer authentication key.
	Link([]byte) (kem.PublicKey, error)

	// Add adds the user identified by the username and public key
	// to the database.  Existing users will have their public keys
	// updated if specified, otherwise an error will be returned.
	Add([]byte, kem.PublicKey, bool) error

	// SetIdentity sets the optional identity key for the user identified
	// by the user name to the provided public key.  Providing a nil key
	// will remove the user's identity key iff it exists.
	SetIdentity([]byte, kem.PublicKey) error

	// Identity returns the optional identity key for the user identified
	// by the user name.
	Identity([]byte) (kem.PublicKey, error)

	// Remove removes the user identified by the username from the database.
	Remove([]byte) error

	// Close closes the UserDB instance.
	Close()
}

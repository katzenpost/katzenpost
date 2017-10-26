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
	"github.com/katzenpost/core/crypto/ecdh"
	"github.com/katzenpost/core/sphinx/constants"
)

// MaxUsernameSize is the maximum username length in bytes.
const MaxUsernameSize = constants.RecipientIDLength

// UserDB is the interface provided by all user database implementations.
type UserDB interface {
	// Exists returns true iff the user identified by the username exists.
	Exists([]byte) bool

	// IsValid returns true iff the user identified by the username and
	// public key is valid.
	IsValid([]byte, *ecdh.PublicKey) bool

	// Add adds the user identified by the username and public key
	// to the database.  Existing users will have their public keys
	// updated if specified, otherwise an error will be returned.
	Add([]byte, *ecdh.PublicKey, bool) error

	// Remove removes the user identified by the username from the database.
	Remove([]byte) error

	// Close closes the UserDB instance.
	Close()
}

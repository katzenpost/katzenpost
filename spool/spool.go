// spool.go - Katzenpost server user message spool.
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

// Package spool defines the Katzenpost server user message spool abstract
// interface.
package spool

import (
	"github.com/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/server/userdb"
)

// Spool is the interface provided by all user messgage spool implementations.
type Spool interface {
	// StoreMessage stores a message in the user's spool.
	StoreMessage(u, msg []byte) error

	// StoreSURBReply stores a SURBReply in the user's spool.
	StoreSURBReply(u []byte, id *[constants.SURBIDLength]byte, msg []byte) error

	// Get optionally deletes the first entry in a user's spool, and returns
	// the (new) first entry.  Both messages and SURBReplies may be returned.
	Get(u []byte, advance bool) (msg, surbID []byte, remaining int, err error)

	// Remove removes the spool identified by the username from the database.
	Remove(u []byte) error

	// Vaccum removes the spools that do not correspond to valid users in the
	// provided UserDB.
	Vaccum(udb userdb.UserDB) error

	// Close closes the Spool instance.
	Close()
}

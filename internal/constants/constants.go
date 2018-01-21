// constants.go - Katzenpost server internal constants.
// Copyright (C) 2018  Yawning Angel.
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

// Package constants defines internal constants for the Katzenpost server.
package constants

import "time"

const (
	// NumMixKeys is the number of mix keys to generate/publish.
	NumMixKeys = 3

	// KeepAliveInterval is the TCP/IP KeepAlive interval.
	KeepAliveInterval = 3 * time.Minute
)

// constants.go - Katzenpost constants.
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

// Package constants contains the constants for Katzenpost.
package constants

import "github.com/katzenpost/core/sphinx"

const (
	// PacketLength is the length of a Sphinx Packet in bytes.
	PacketLength = sphinx.SURBLength + ForwardPayloadLength

	// ForwardPayloadLength is the length of the usable forward payload of a
	// Sphinx Packet in bytes.
	ForwardPayloadLength = 50 * 1024
)

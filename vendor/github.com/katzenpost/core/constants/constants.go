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
	PacketLength = sphinx.HeaderLength + sphinx.PayloadTagLength + ForwardPayloadLength

	// SphinxPlaintextHeaderLength is the length of a BlockSphinxPlaintext
	// in bytes.
	SphinxPlaintextHeaderLength = 1 + 1

	// ForwardPayloadLength is the length of the usable forward payload of a
	// Sphinx Packet in bytes.  This is named `SURB_PAYLOAD_LENGTH` in the
	// End to End spec due to packets constructed using a SURB having the
	// SURB's space available for payload.  The Sphinx spec calls this
	// `PAYLOAD_LENGTH`, since the Sphinx spec is agnostic to how SURBs are
	// transported.
	ForwardPayloadLength = 50 * 1024

	// UserForwardPayloadLength is the length of user portion of the forward
	// payload.  The End to End spec calls this `PAYLOAD_LENGTH` but this is
	// somewhat shorter than the `PAYLOAD_LENGTH` as defined in the Sphinx
	// spec.
	UserForwardPayloadLength = ForwardPayloadLength - (SphinxPlaintextHeaderLength + sphinx.SURBLength)
)

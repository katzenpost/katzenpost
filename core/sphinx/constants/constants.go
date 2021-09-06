// constants.go - Sphinx Packet Format constants.
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

// Package constants contains the Sphinx Packet Format constants for the
// Katzenpost parameterization.
package constants

const (
	// NodeIDLength is the node identifier length in bytes.
	NodeIDLength = 32

	// RecipientIDLength is the recipient identifier length in bytes.
	RecipientIDLength = 64

	// SURBIDLength is the SURB identifier length in bytes.
	SURBIDLength = 16

	// NrHops is the number of hops a packet will traverse.
	NrHops = 5
)

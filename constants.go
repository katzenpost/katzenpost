// SPDX-FileCopyrightText: 2019, David Stainton <dawuud@riseup.net>
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// constants.go - catshadow constants
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

package catshadow

import (
	"time"

	ratchet "github.com/katzenpost/doubleratchet"
	"github.com/katzenpost/memspool/common"
)

// DoubleRatchetPayloadLength is the length of the payload encrypted by the ratchet.
var DoubleRatchetPayloadLength = common.SpoolPayloadLength - ratchet.DoubleRatchetOverhead

const (
	// MessageExpirationDuration is the duration of time after which messages will be removed.
	MessageExpirationDuration = 168 * time.Hour

	// MessageIDLen is the length of our message IDs which are used the keys in a map
	// to reference individual messages of a conversation.
	MessageIDLen = 4

	// GarbageCollectionInterval is the time interval between garbage collecting
	// old messages.
	GarbageCollectionInterval = 120 * time.Minute
)

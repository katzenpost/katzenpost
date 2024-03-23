// constants.go - mixnet client constants
// Copyright (C) 2018  David Stainton.
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

package constants

import (
	"time"
)

const (
	// MessageIDLength is the length of a message ID in bytes.
	MessageIDLength = 16

	// RoundTripTimeSlop is the slop added to the expected packet
	// round trip timeout threshold. Used for GC and for blocking
	// on reply in Session's BlockingSendUnreliableMessage method.
	RoundTripTimeSlop = 4 * time.Second

	// TimeSkewWarnDelta is the client connection time skew threshold
	// where clients print a warning log entry.
	TimeSkewWarnDelta = 2 * time.Minute

	// LoopService is the name of the Katzenpost loop service.
	LoopService = "echo"

	// GarbageCollectionInterval is the time interval between running our
	// SURB ID Map garbage collection routine.
	GarbageCollectionInterval = 10 * time.Minute

	// MaxEgressQueueSize is the maximum size of the egress queue.
	MaxEgressQueueSize = 40
)

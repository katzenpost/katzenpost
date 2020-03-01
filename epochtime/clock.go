// clock.go - Reunion epoch clock.
// Copyright (C) 2020  David Stainton.
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

// Package epochtime provides the Reunion protocol epoch timer.
package epochtime

import (
	"time"
)

// EpochClock the interface which Reunion uses for epoch clocks.
type EpochClock interface {
	// Now returns the current epoch, time since the start of the
	// current epoch, and time till the next epoch.
	Now() (current uint64, elapsed, till time.Duration)

	// Period returns the epoch duration.
	Period() time.Duration
}

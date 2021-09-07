// clock.go - Reunion Katzenpost epoch clock.
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

// Package katzenpost provides the Reunion protocol Katzenpost epoch timer.
package katzenpost

import (
	"time"

	"github.com/katzenpost/katzenpost/core/epochtime"
)

// Clock provides an implemention of the Reunion EpochClock interface for
// the Katzenpost epoch timer.
type Clock struct{}

// Now returns the current Katzenpost epoch, time since the start of the
// current epoch, and time till the next epoch.
func (t *Clock) Now() (current uint64, elapsed, till time.Duration) {
	return epochtime.Now()
}

// Period returns the epoch duration.
func (t *Clock) Period() time.Duration {
	return epochtime.Period
}

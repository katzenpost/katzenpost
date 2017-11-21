// time.go - Katzenpost epoch time.
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

// Package epochtime implements Katzenpost epoch related timekeeping functions.
package epochtime

import "time"

// Period is the duration of a Katzenpost epoch.
const Period = 3 * time.Hour

var Epoch = time.Date(2017, 6, 1, 0, 0, 0, 0, time.UTC)

// Now returns the current Katzenpost epoch, time since the start of the
// current, and time till the next epoch.
func Now() (current uint64, elapsed, till time.Duration) {
	// Cache now for a consistent value for this query.
	now := time.Now()

	fromEpoch := time.Since(Epoch)
	if fromEpoch < 0 {
		panic("epochtime: BUG: system time appears to predate the epoch")
	}

	current = uint64(fromEpoch / Period)

	base := Epoch.Add(time.Duration(current) * Period)
	elapsed = now.Sub(base)
	till = base.Add(Period).Sub(now)
	return
}

// IsInEpoch returns true iff the epoch e contains the time t, measured in the
// number of seconds since the UNIX epoch.
func IsInEpoch(e uint64, t uint64) bool {
	deltaStart := time.Duration(e) * Period
	deltaEnd := time.Duration(e+1) * Period

	startTime := Epoch.Add(deltaStart)
	endTime := Epoch.Add(deltaEnd)

	tt := time.Unix(int64(t), 0)

	if tt.Equal(startTime) {
		return true
	}
	return tt.After(startTime) && tt.Before(endTime)
}

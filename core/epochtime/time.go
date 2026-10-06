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

import (
	"sync/atomic"
	"time"
)

const DefaultPeriod = 20 * time.Minute

var period atomic.Int64

func Period() time.Duration {
	if p := period.Load(); p != 0 {
		return time.Duration(p)
	}
	return DefaultPeriod
}

// Epoch is the Katzenpost epoch expressed in UTC.
var Epoch = time.Date(2017, 6, 1, 0, 0, 0, 0, time.UTC)

// WeekOfEpochs is the number of epochs in a week
func WeekOfEpochs() uint64 { return uint64(time.Duration(time.Hour*24*7) / Period()) }

// Now returns the current Katzenpost epoch, time since the start of the
// current epoch, and time till the next epoch.
func Now() (current uint64, elapsed, till time.Duration) {
	return getEpoch(time.Now())
}

// IsInEpoch returns true iff the epoch e contains the time t, measured in the
// number of seconds since the UNIX epoch.
func IsInEpoch(e uint64, t uint64) bool {
	p := Period()
	deltaStart := time.Duration(e) * p
	deltaEnd := time.Duration(e+1) * p

	startTime := Epoch.Add(deltaStart)
	endTime := Epoch.Add(deltaEnd)

	tt := time.Unix(int64(t), 0)

	if tt.Equal(startTime) {
		return true
	}
	return tt.After(startTime) && tt.Before(endTime)
}

// FromUnix returns the Katzenpost epoch, time since the start of the current
// epoch, and time till the next epoch relative to a Unix time in seconds.
func FromUnix(t int64) (current uint64, elapsed, till time.Duration) {
	return getEpoch(time.Unix(t, 0))
}

func getEpoch(t time.Time) (current uint64, elapsed, till time.Duration) {
	fromEpoch := t.Sub(Epoch)
	if fromEpoch < 0 {
		panic("epochtime: BUG: time appears to predate the epoch")
	}

	p := Period()
	current = uint64(fromEpoch / p)

	base := Epoch.Add(time.Duration(current) * p)
	elapsed = t.Sub(base)
	till = base.Add(p).Sub(t)
	return
}

// monotime.go - Monotonic clock.
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

// Package monotime implements a monotonic clock.
package monotime

import (
	"time"
)

// Now returns the current time as measured by a monotonic clock source.  The
// value is totally unrelated to civil time, and should only be used for
// measuring relative time intervals.
func Now() time.Duration {
	return nowImpl()
}

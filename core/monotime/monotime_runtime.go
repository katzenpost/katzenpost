// monotime_runtime.go - Go Runtime Monotonic clock.
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

// +build go1.9

package monotime

import (
	"time"
)

var monoBase time.Time

func nowImpl() time.Duration {
	// Go 1.9 and above has monotonic time support as part of time.Time.
	//
	// This routine when built against the appropriate runtime is a thin stub
	// that just returns the delta-T from when the package was initialized.
	return time.Since(monoBase)
}

func init() {
	monoBase = time.Now()
}

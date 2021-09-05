// monotime_test.go - Monotonic clock tests.
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

package monotime

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestMonotime(t *testing.T) {
	require := require.New(t)

	// Ensure that using the monotonic clock source actually appears to work.
	require.NotPanics(func() { Now() }, "Basic Now() sanity check")

	// Validate timekeeping, by sleeping for a fixed interval and ensuring that
	// the monotonic clock advances by approximately how much we expect.
	const sleepTime = 100 * time.Millisecond

	before := Now()
	time.Sleep(sleepTime)
	after := Now()

	require.InEpsilon(int64(sleepTime), int64(after-before), 0.05, "Interval subtraction")
}

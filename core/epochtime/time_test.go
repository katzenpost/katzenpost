// time_test.go - Epoch time tests.
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

package epochtime

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEpochTime(t *testing.T) {
	require := require.New(t)

	var now uint64
	var elapsed, till time.Duration
	require.NotPanics(func() { now, elapsed, till = Now() }, "Basic Now() sanity check")
	t.Logf("Epoch: %v, Elapsed: %v Till: %v", now, elapsed, till)
}

func TestIsInEpoch(t *testing.T) {
	assert := assert.New(t)
	e, _, _ := Now()
	now := uint64(time.Now().Unix())

	assert.True(IsInEpoch(e, now), "IsInEpoch(e, now)")

	nextNow := now + 3*60*60
	assert.False(IsInEpoch(e, nextNow), "IsInEpoch(e, now+3h)")

	prevNow := now - 3*60*60
	assert.False(IsInEpoch(e, prevNow), "IsInEpoch(e, now-3h)")
}

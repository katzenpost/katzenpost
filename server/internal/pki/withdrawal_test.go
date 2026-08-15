// withdrawal_test.go - Descriptor withdrawal tests.
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

package pki

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/server/internal/pkicache"
)

func TestStopAdvertisingCancelsAndWaitsForPublication(t *testing.T) {
	require := require.New(t)
	p := &pki{
		advertising: true,
		docs: map[uint64]*pkicache.Entry{
			42: nil,
		},
	}

	publicationCtx, publicationDone, ok := p.beginDescriptorPublication(context.Background())
	require.True(ok)
	p.recordDescriptorAdvertisement(41)

	canceled := make(chan struct{})
	release := make(chan struct{})
	go func() {
		<-publicationCtx.Done()
		close(canceled)
		<-release
		p.endDescriptorPublication(publicationDone)
	}()

	stopped := make(chan uint64, 1)
	go func() {
		stopped <- p.StopAdvertising()
	}()

	<-canceled
	select {
	case <-stopped:
		t.Fatal("StopAdvertising returned before the active publication ended")
	default:
	}

	close(release)
	require.Equal(uint64(42), <-stopped,
		"cached consensus epoch must extend the conservative withdrawal wait")

	_, _, ok = p.beginDescriptorPublication(context.Background())
	require.False(ok, "publication must remain disabled after withdrawal starts")
	require.Equal(uint64(42), p.StopAdvertising(), "StopAdvertising must be idempotent")
}

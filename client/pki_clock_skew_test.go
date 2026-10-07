// SPDX-License-Identifier: AGPL-3.0-only

package client

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/epochtime"
)

func TestSkewedUnixTimeFollowsTheGatewayClock(t *testing.T) {
	const localAheadOfGateway = 100
	p, _ := newRefetchPKI(t, true)
	p.setClockSkew(localAheadOfGateway)
	gateway := time.Now().Unix() - localAheadOfGateway
	require.InDelta(t, gateway, p.skewedUnixTime(), 2)

	p.setClockSkew(-localAheadOfGateway)
	gateway = time.Now().Unix() + localAheadOfGateway
	require.InDelta(t, gateway, p.skewedUnixTime(), 2)
}

func TestClockSkewBeyondAPhaseIsRefused(t *testing.T) {
	limit := int64((epochtime.Period() / 8).Seconds())
	p, _ := newRefetchPKI(t, true)
	skew := func() int64 {
		p.clockSkewLock.RLock()
		defer p.clockSkewLock.RUnlock()
		return p.clockSkew
	}
	for _, sign := range []int64{1, -1} {
		p.setClockSkew(sign * limit)
		require.Equal(t, sign*limit, skew())

		p.setClockSkew(sign * (limit + 1))
		require.Equal(t, sign*limit, skew())

		p.setClockSkew(sign * 10 * limit)
		require.Equal(t, sign*limit, skew())
		require.InDelta(t, time.Now().Unix()-sign*limit, p.skewedUnixTime(), 2)
	}
}

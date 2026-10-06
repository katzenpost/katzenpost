// SPDX-License-Identifier: AGPL-3.0-only

package client

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestSkewedUnixTimeFollowsTheGatewayClock(t *testing.T) {
	const localAheadOfGateway = 600
	p, _ := newRefetchPKI(t, true)
	p.setClockSkew(localAheadOfGateway)
	gateway := time.Now().Unix() - localAheadOfGateway
	require.InDelta(t, gateway, p.skewedUnixTime(), 2)

	p.setClockSkew(-localAheadOfGateway)
	gateway = time.Now().Unix() + localAheadOfGateway
	require.InDelta(t, gateway, p.skewedUnixTime(), 2)
}

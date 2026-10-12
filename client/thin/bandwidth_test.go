// SPDX-License-Identifier: AGPL-3.0-only

package thin

import (
	"crypto/rand"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	ecdh "github.com/katzenpost/hpqc/nike/x25519"

	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/katzenpost/katzenpost/core/wire/commands"
)

func TestEstimateBandwidth(t *testing.T) {
	small := geo.GeometryFromUserForwardPayloadLength(ecdh.Scheme(rand.Reader), 2000, true, 5)
	large := geo.GeometryFromUserForwardPayloadLength(ecdh.Scheme(rand.Reader), 30000, true, 5)
	day := float64(24 * 60 * 60)
	cases := []struct {
		name    string
		lambdaP float64
		lambdaL float64
		decoys  bool
		geo     *geo.Geometry
		docLen  int
		epoch   time.Duration
		pps     float64
		docDay  float64
	}{
		{"decoys on", 0.001, 0.0005, true, small, 100000, 20 * time.Minute, 1.5, 7200000},
		{"decoys off drop the loop rate", 0.001, 0.0005, false, small, 100000, 20 * time.Minute, 1, 7200000},
		{"larger geometry", 0.001, 0.0005, true, large, 0, 20 * time.Minute, 1.5, 0},
		{"short epochs fetch more", 0.002, 0, true, small, 50000, 2 * time.Minute, 2, 36000000},
		{"no rates", 0, 0, true, small, 0, 20 * time.Minute, 0, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := EstimateBandwidth(tc.lambdaP, tc.lambdaL, tc.decoys, tc.geo, tc.docLen, tc.epoch)
			c := commands.NewMixnetCommands(tc.geo)
			require.InDelta(t, tc.pps, b.PacketsPerSecond, 1e-9)
			require.InDelta(t, tc.pps*day*float64(c.MaxMessageLenClientToServer), b.UpBytesPerDay, 1e-3)
			require.InDelta(t, tc.pps*day*float64(c.MaxMessageLenServerToClient), b.DownBytesPerDay, 1e-3)
			require.InDelta(t, tc.docDay, b.DocBytesPerDay, 1e-3)
		})
	}
	on := EstimateBandwidth(0.001, 0, true, small, 0, 20*time.Minute)
	big := EstimateBandwidth(0.001, 0, true, large, 0, 20*time.Minute)
	require.Greater(t, big.UpBytesPerDay, on.UpBytesPerDay)
	require.Contains(t, on.String(), "1.00 packets/s")
	require.Contains(t, on.String(), "MiB/day")
}

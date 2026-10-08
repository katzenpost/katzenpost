// SPDX-License-Identifier: AGPL-3.0-only

package thin

import (
	"fmt"
	"time"

	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/katzenpost/katzenpost/core/wire/commands"
)

type Bandwidth struct {
	PacketsPerSecond float64
	UpBytesPerDay    float64
	DownBytesPerDay  float64
	DocBytesPerDay   float64
}

func EstimateBandwidth(lambdaP, lambdaL float64, decoys bool, g *geo.Geometry, docLen int, epoch time.Duration) Bandwidth {
	rate := lambdaP
	if decoys {
		rate += lambdaL
	}
	pps := rate * 1000
	day := (24 * time.Hour).Seconds()
	c := commands.NewMixnetCommands(g)
	return Bandwidth{
		PacketsPerSecond: pps,
		UpBytesPerDay:    pps * day * float64(c.MaxMessageLenClientToServer),
		DownBytesPerDay:  pps * day * float64(c.MaxMessageLenServerToClient),
		DocBytesPerDay:   float64(docLen) * float64(24*time.Hour) / float64(epoch),
	}
}

func (b Bandwidth) String() string {
	const mib = 1 << 20
	return fmt.Sprintf("%.2f packets/s, up %.1f MiB/day, down %.1f MiB/day, consensus %.1f MiB/day",
		b.PacketsPerSecond, b.UpBytesPerDay/mib, b.DownBytesPerDay/mib, b.DocBytesPerDay/mib)
}

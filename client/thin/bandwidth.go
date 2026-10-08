// SPDX-License-Identifier: AGPL-3.0-only

package thin

import (
	"time"

	"github.com/katzenpost/katzenpost/core/sphinx/geo"
)

type Bandwidth struct {
	PacketsPerSecond float64
	UpBytesPerDay    float64
	DownBytesPerDay  float64
	DocBytesPerDay   float64
}

func EstimateBandwidth(lambdaP, lambdaL float64, decoys bool, g *geo.Geometry, docLen int, epoch time.Duration) Bandwidth {
	return Bandwidth{}
}

func (b Bandwidth) String() string {
	return ""
}

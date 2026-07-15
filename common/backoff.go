// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package common

import (
	"time"

	"github.com/katzenpost/hpqc/rand"
)

// JitterDelay returns d scaled by a uniform random factor in [0.5, 1.5).
// Applied to reconnect backoff so a fleet of peers redialing a restarting
// node does not synchronize into a thundering herd. A zero or negative d
// is returned unchanged.
func JitterDelay(d time.Duration) time.Duration {
	if d <= 0 {
		return d
	}
	factor := 0.5 + rand.NewMath().Float64()
	return time.Duration(float64(d) * factor)
}

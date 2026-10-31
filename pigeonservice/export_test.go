// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package pigeonservice

import "time"

// SetRescanInterval sets how often services look for new routers.
func SetRescanInterval(d time.Duration) (restore func()) {
	old := rescanInterval
	rescanInterval = d
	return func() { rescanInterval = old }
}

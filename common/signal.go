// SPDX-License-Identifier: AGPL-3.0-only

package common

import "os"

func RotateOnSignal(ch <-chan os.Signal, rotate func()) {
	for range ch {
		rotate()
	}
}

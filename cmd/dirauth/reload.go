// SPDX-License-Identifier: AGPL-3.0-only

package main

import "os"

func reloadOnSignal(ch <-chan os.Signal, reload func()) {
	for range ch {
		reload()
	}
}

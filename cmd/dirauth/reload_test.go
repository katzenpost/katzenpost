// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestReloadOnSignalReloadsOnEverySignal(t *testing.T) {
	ch := make(chan os.Signal)
	n := 0
	done := make(chan struct{})
	go func() {
		reloadOnSignal(ch, func() { n++ })
		close(done)
	}()
	for range 3 {
		ch <- os.Interrupt
	}
	close(ch)
	<-done
	require.Equal(t, 3, n)
}

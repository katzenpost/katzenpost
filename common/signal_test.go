// SPDX-License-Identifier: AGPL-3.0-only

package common

import (
	"os"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRotateOnSignalEverySignal(t *testing.T) {
	ch := make(chan os.Signal)
	n := 0
	done := make(chan struct{})
	go func() {
		RotateOnSignal(ch, func() { n++ })
		close(done)
	}()
	for range 3 {
		ch <- syscall.SIGHUP
	}
	close(ch)
	<-done
	require.Equal(t, 3, n)
}

func TestRotateOnSignalNone(t *testing.T) {
	ch := make(chan os.Signal)
	close(ch)
	n := 0
	RotateOnSignal(ch, func() { n++ })
	require.Equal(t, 0, n)
}

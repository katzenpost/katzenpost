// SPDX-License-Identifier: AGPL-3.0-only

//go:build !windows

package main

import (
	"os"
	"os/signal"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestNotifyReloadDeliversSIGUSR1(t *testing.T) {
	ch := make(chan os.Signal, 1)
	notifyReload(ch)
	defer signal.Stop(ch)
	require.NoError(t, syscall.Kill(os.Getpid(), syscall.SIGUSR1))
	select {
	case sig := <-ch:
		require.Equal(t, syscall.SIGUSR1, sig)
	case <-time.After(5 * time.Second):
		t.Fatal("SIGUSR1 was not delivered to the reload channel")
	}
}

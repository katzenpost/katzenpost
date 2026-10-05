// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestSendToPeerHonoursConfiguredMaxAttempts(t *testing.T) {
	sender := retryTestSender(t)
	sender.s.cfg.Server.PeerRetryMaxAttempts = 2
	var dials int32
	sender.dialContextFn = func(ctx context.Context, network, addr string) (net.Conn, error) {
		atomic.AddInt32(&dials, 1)
		return nil, errors.New("connection refused")
	}
	start := time.Now()
	_, err := sender.sendCommandToPeerWithDeadline(retryTestPeer(), retryTestCert(sender), start.Add(10*time.Second))
	require.Error(t, err)
	require.Equal(t, int32(3), atomic.LoadInt32(&dials))
	require.Less(t, time.Since(start), 5*time.Second)
}

func TestSendToPeerUnsetMaxAttemptsRetriesToDeadline(t *testing.T) {
	sender := retryTestSender(t)
	sender.s.cfg.Server.PeerRetryMaxAttempts = 0
	var dials int32
	sender.dialContextFn = func(ctx context.Context, network, addr string) (net.Conn, error) {
		atomic.AddInt32(&dials, 1)
		return nil, errors.New("connection refused")
	}
	start := time.Now()
	_, err := sender.sendCommandToPeerWithDeadline(retryTestPeer(), retryTestCert(sender), start.Add(300*time.Millisecond))
	require.Error(t, err)
	require.Greater(t, atomic.LoadInt32(&dials), int32(3))
	require.GreaterOrEqual(t, time.Since(start), 250*time.Millisecond)
}

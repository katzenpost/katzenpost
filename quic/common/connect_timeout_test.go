// SPDX-License-Identifier: AGPL-3.0-only

package common

import (
	"context"
	"net"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestDialURLQuicHandshakeWaitsForTheConnectDeadline(t *testing.T) {
	const connectTimeout = 7 * time.Second
	silent, err := net.ListenPacket("udp", "127.0.0.1:0")
	require.NoError(t, err)
	defer silent.Close()
	u, err := url.Parse("quic://" + silent.LocalAddr().String())
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), connectTimeout)
	defer cancel()
	start := time.Now()
	_, err = DialURL(u, ctx, nil)
	elapsed := time.Since(start)
	require.Error(t, err)
	require.GreaterOrEqual(t, elapsed, connectTimeout-time.Second, "the quic handshake gave up after %v, before the %v connect deadline: %v", elapsed, connectTimeout, err)
}

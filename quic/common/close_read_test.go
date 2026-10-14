// SPDX-License-Identifier: AGPL-3.0-only

package common

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestReadAfterCloseReturnsPromptly(t *testing.T) {
	l, client, server := quicPair(t)
	defer l.Close()
	defer client.Close()
	require.NoError(t, server.Close())
	time.Sleep(50 * time.Millisecond)
	start := time.Now()
	var b [1]byte
	_, err := server.Read(b[:])
	require.ErrorIs(t, err, net.ErrClosed)
	require.Less(t, time.Since(start), closeLinger/4, "a Read after Close waited on the close linger")
}

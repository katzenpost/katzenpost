// SPDX-License-Identifier: AGPL-3.0-only

//go:build windows

package outgoing

import (
	"net"
	"os"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/wire"
)

func TestIsConnResetWindows(t *testing.T) {
	reset := &net.OpError{Op: "wsarecv", Net: "tcp", Err: os.NewSyscallError("wsarecv", syscall.WSAECONNRESET)}
	require.True(t, isConnReset(reset))
	require.True(t, refusedBeforeHandshake(&wire.HandshakeError{IsInitiator: true, State: wire.HandshakeStateMsg2Receive, UnderlyingError: reset}))
}

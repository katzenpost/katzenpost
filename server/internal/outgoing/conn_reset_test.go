// SPDX-License-Identifier: AGPL-3.0-only

package outgoing

import (
	"io"
	"net"
	"os"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestIsConnReset(t *testing.T) {
	require.True(t, isConnReset(&net.OpError{Op: "read", Net: "tcp", Err: os.NewSyscallError("read", syscall.ECONNRESET)}))
	require.False(t, isConnReset(io.EOF))
	require.False(t, isConnReset(timeoutError{}))
	require.False(t, isConnReset(nil))
}

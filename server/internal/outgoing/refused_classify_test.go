// SPDX-License-Identifier: AGPL-3.0-only

package outgoing

import (
	"errors"
	"io"
	"net"
	"os"
	"strings"
	"syscall"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/wire"
)

type timeoutError struct{}

func (timeoutError) Error() string   { return "i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

func TestRefusedBeforeHandshakeClassifier(t *testing.T) {
	reset := &net.OpError{Op: "read", Net: "tcp", Err: os.NewSyscallError("read", syscall.ECONNRESET)}
	he := func(initiator bool, state wire.HandshakeState, size int, err error) error {
		return &wire.HandshakeError{IsInitiator: initiator, State: state, MessageSize: size, UnderlyingError: err}
	}
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{"eof", he(true, wire.HandshakeStateMsg2Receive, 0, io.EOF), true},
		{"reset", he(true, wire.HandshakeStateMsg2Receive, 0, reset), true},
		{"responder", he(false, wire.HandshakeStateMsg2Receive, 0, io.EOF), false},
		{"other state", he(true, wire.HandshakeStateMsg1Send, 0, io.EOF), false},
		{"partial message", he(true, wire.HandshakeStateMsg2Receive, 7, io.EOF), false},
		{"timeout", he(true, wire.HandshakeStateMsg2Receive, 0, timeoutError{}), false},
		{"not a handshake error", io.EOF, false},
		{"nil", nil, false},
		{"wrapped", errors.Join(errors.New("dial"), he(true, wire.HandshakeStateMsg2Receive, 0, io.EOF)), true},
	} {
		require.Equal(t, tc.want, refusedBeforeHandshake(tc.err), tc.name)
	}
}

func TestSilentPeerTimeoutIsAnError(t *testing.T) {
	out := handshakeLog(t, func(c net.Conn) {
		defer c.Close()
		io.Copy(io.Discard, c)
	})
	require.True(t, strings.Contains(out, "ERRO") && strings.Contains(out, "Handshake failed"), out)
}

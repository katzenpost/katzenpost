// SPDX-License-Identifier: AGPL-3.0-only

package common

import (
	"net"
	"testing"

	"github.com/quic-go/quic-go"
	"github.com/stretchr/testify/require"
)

func TestQuicListenerAcceptAfterCloseIsPermanent(t *testing.T) {
	ql, err := quic.ListenAddr("127.0.0.1:0", GenerateTLSConfig(), nil)
	require.NoError(t, err)
	l := &QuicListener{Listener: ql}
	require.NoError(t, l.Close())
	_, err = l.Accept()
	require.Error(t, err)
	ne, ok := err.(net.Error)
	require.True(t, ok, "accept error %T %v is not a net.Error", err, err)
	require.False(t, ne.Temporary())
}

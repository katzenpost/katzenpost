package client2

import (
	"net"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"
)

func TestListener(t *testing.T) {
	s, err := NewListener(123)
	require.NoError(t, err)

	srcUnixAddr, err := net.ResolveUnixAddr("unixpacket", "@testapp1")
	require.NoError(t, err)

	destUnixAddr, err := net.ResolveUnixAddr("unixpacket", "@katzenpost")
	require.NoError(t, err)

	conn, err := net.DialUnix("unixpacket", srcUnixAddr, destUnixAddr)
	require.NoError(t, err)

	time.Sleep(500 * time.Millisecond)

	req := new(Request)
	req.ID = 1234
	req.Operation = []byte("hello")
	req.Payload = []byte("yoyoyo")

	requestCbor, err := cbor.Marshal(req)
	require.NoError(t, err)

	oob := make([]byte, 0)

	count, oobCount, err := conn.WriteMsgUnix(requestCbor, oob, destUnixAddr)
	require.NoError(t, err)
	require.Equal(t, count, len(requestCbor))
	require.Equal(t, oobCount, 0)

	t.Logf("WriteMsgUnix: count is %d, oob count is %d", count, oobCount)

	time.Sleep(2000 * time.Millisecond)

	s.Halt()
}

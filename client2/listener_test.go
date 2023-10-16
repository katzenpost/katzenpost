package client2

import (
	"net"
	"os"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"
)

func NoTestListenerEchoOperation(t *testing.T) {

	rates := &Rates{}
	egressCh := make(chan *Request)
	listener, err := NewListener(nil, rates, egressCh, os.Stderr)
	require.NoError(t, err)

	srcUnixAddr, err := net.ResolveUnixAddr("unixpacket", "@testapp1")
	require.NoError(t, err)

	destUnixAddr, err := net.ResolveUnixAddr("unixpacket", "@katzenpost")
	require.NoError(t, err)

	conn, err := net.DialUnix("unixpacket", srcUnixAddr, destUnixAddr)
	require.NoError(t, err)

	time.Sleep(500 * time.Millisecond)

	req := new(Request)
	req.AppID = 1234
	req.IsEchoOp = true
	req.Payload = []byte("yoyoyo")

	requestCbor, err := cbor.Marshal(req)
	require.NoError(t, err)

	count, oobCount, err := conn.WriteMsgUnix(requestCbor, nil, destUnixAddr)
	require.NoError(t, err)
	require.Equal(t, count, len(requestCbor))
	require.Equal(t, oobCount, 0)

	t.Logf("WriteMsgUnix: count is %d, oob count is %d", count, oobCount)

	time.Sleep(200 * time.Millisecond)

	t.Log("ReadMsgUnix")

	buff := make([]byte, 65536)
	count, _, _, _, err = conn.ReadMsgUnix(buff, nil)

	response := new(Response)
	err = cbor.Unmarshal(buff[:count], response)
	require.NoError(t, err)
	require.Equal(t, response.AppID, req.AppID)
	require.Equal(t, response.Payload, req.Payload)

	listener.Halt()
}

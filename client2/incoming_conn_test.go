package client2

import (
	"net"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/rand"
	"github.com/katzenpost/katzenpost/client2/config"
	"github.com/katzenpost/katzenpost/client2/thin"
	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/core/sphinx/constants"
)

func TestThinClientSendToDaemon(t *testing.T) {
	conn1, conn2 := net.Pipe()

	logBackend, err := log.New("", "debug", false)
	require.NoError(t, err)
	l := &listener{
		logBackend: logBackend,
		isTCP:      true,
	}

	incomingConn := newIncomingConn(l, conn1)

	done := make(chan struct{})

	go func() {
		_, err := incomingConn.recvRequest()
		require.NoError(t, err)
		done <- struct{}{}
	}()

	cfg, err := config.LoadFile("testdata/client.toml")
	require.NoError(t, err)

	client := thin.NewThinClient(cfg)
	client.Conn = conn2

	surbid := &[constants.SURBIDLength]byte{}
	_, err = rand.Reader.Read(surbid[:])
	require.NoError(t, err)

	payload := []byte("hello my name is Bob")

	destNode := &[32]byte{}
	_, err = rand.Reader.Read(destNode[:])
	require.NoError(t, err)

	destQueue := []byte("queue123")

	err = client.SendMessage(surbid, payload, destNode, destQueue)
	require.NoError(t, err)

	<-done
}

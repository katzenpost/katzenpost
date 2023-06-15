package common

import (
	"context"
	"testing"
	"net"
	"github.com/katzenpost/katzenpost/core/log"
	"sync"
	"github.com/stretchr/testify/require"
)

var payloadSize = 1500
func TestKatConn(t *testing.T) {
	require := require.New(t)
	logBackend, err := log.New("", "DEBUG", false)
	require.NoError(err)
	sender := NewKatConn(logBackend.GetLogger("senderConn"))
	receiver := NewKatConn(logBackend.GetLogger("receiverConn"))


	ctx := context.Background()
	wg := new(sync.WaitGroup)
	var sConn, rConn net.Conn
	wg.Add(3)
	errCh := make(chan error,3)
	go func() {
		sConn, err = sender.Dial(ctx, receiver.LocalAddr())
		if err != nil {
			errCh <-err
		} else {
			errCh <- nil
		}
	}()

	// these routines mimic the kaetzchen service
	// read from sender, write to receiver
	go func() {
		for {
			pkt := make([]byte, payloadSize)
			_, err := sender.ReadPacket(pkt)
			if err != nil {
				errCh <- err
				return
			}
			_, err = receiver.WritePacket(pkt[:])
			if err != nil {
				errCh <- err
				return
			}

		}
	}()
	// read from receiver, write to sender
	go func() {
		for {
			pkt := make([]byte, payloadSize)
			_, err := receiver.ReadPacket(pkt)
			if err != nil {
				errCh <- err
				return
			}

			_, err = sender.WritePacket(pkt)
			if err != nil {
				errCh <- err
				return
			}

		}
	}()
	go func() {
		for {
			err, ok := <-errCh
			if !ok {
				return
			}
			if err != nil {
				panic(err)
			}
		}
	}()

	rConn, err = receiver.Accept(ctx)
	require.NoError(err)

	msg1 := []byte("Hello world")
	_, err = sConn.Write(msg1)
	require.NoError(err)
	p := make([]byte, len(msg1))
	_, err = rConn.Read(p)
	require.NoError(err)
	require.Equal(p, msg1)
	err = sConn.Close()
	require.NoError(err)
}

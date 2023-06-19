package common

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync"
	"testing"

	"github.com/katzenpost/katzenpost/core/crypto/rand"
	"github.com/stretchr/testify/require"
)

var payloadSize = 1452 // this is the minimum valid QUIC packet payload size

func TestQUICProxyConnSimple(t *testing.T) {
	require := require.New(t)
	k := NewQUICProxyConn("simple")
	pkt := make([]byte, payloadSize)
	cpy := make([]byte, payloadSize)
	n, err := k.WritePacket(pkt, k.LocalAddr())
	require.NoError(err)
	n2, addr, err := k.ReadFrom(cpy)
	require.NoError(err)
	require.NotNil(addr)
	require.Equal(n, n2)
	require.Equal(pkt, cpy)
}

func TestQUICProxyConn(t *testing.T) {
	require := require.New(t)
	sender := NewQUICProxyConn("sender")
	receiver := NewQUICProxyConn("receiver")

	msg1 := make([]byte, 42*42*42)
	_, err := io.ReadFull(rand.Reader, msg1)
	require.NoError(err)
	ctx := context.Background()
	peers := new(sync.WaitGroup)
	peers.Add(2)
	workers := new(sync.WaitGroup)
	workers.Add(2)
	errCh := make(chan error, 42)

	// start the dialer (client)
	go func() {
		defer peers.Done()
		t.Logf("dialing: %s", receiver.LocalAddr().String())
		sConn, err := sender.Dial(ctx, receiver.LocalAddr())
		if err != nil {
			errCh <- err
			return
		} else {
			_, err = sConn.Write(msg1)
			if err != nil {
				errCh <- err
				return
			}
		}
	}()

	// start the receiver
	go func() {
		defer peers.Done()
		t.Logf("accepting: %s", receiver.LocalAddr().String())
		rConn, err := receiver.Accept(ctx)
		if err != nil {
			errCh <- err
			return
		}
		p := make([]byte, len(msg1))

		n, err := io.ReadFull(rConn, p)
		if err != nil {
			if n == 0 {
				errCh <- err
				return
			} else {
				panic("error but also read something")
			}
		}
		if !bytes.Equal(p, msg1) {
			errCh <- errors.New("Payload mismatch")
		}
		err = rConn.Close()
		if err != nil {
			errCh <- err
		}
		t.Logf("Halting receiver")
		receiver.Halt()
	}()

	// these routines mimic the kaetzchen service
	// read from sender, write to receiver
	go func() {
		defer workers.Done()
		src := sender.LocalAddr()
		for {
			pkt := make([]byte, payloadSize)
			n, addr, err := sender.ReadPacket(pkt)
			if err == errHalted {
				return
			} else if err != nil {
				errCh <- err
				return
			}
			if addr.String() != receiver.LocalAddr().String() {
				errCh <- errors.New("Address mismatch")
				return
			}
			_, err = receiver.WritePacket(pkt[:n], src)
			if err != nil {
				errCh <- err
				return
			}
		}
	}()
	// read from receiver, write to sender
	go func() {
		defer workers.Done()
		for {
			pkt := make([]byte, payloadSize)
			n, addr, err := receiver.ReadPacket(pkt)
			if err == errHalted {
				return
			} else if err != nil {
				errCh <- err
				return
			}
			if addr.String() != sender.LocalAddr().String() {
				errCh <- errors.New("Address mismatch")
				return
			}
			_, err = sender.WritePacket(pkt[:n], receiver.LocalAddr())
			if err != nil {
				errCh <- err
				return
			}
		}
	}()

	peers.Wait()
	t.Logf("Halting sender and receiver worker")
	sender.Halt()
	receiver.Halt()
	workers.Wait()

	// check for any received unexpected errors
	close(errCh)
	for {
		err, ok := <-errCh
		if !ok {
			return
		}
		require.NoError(err)
	}
}

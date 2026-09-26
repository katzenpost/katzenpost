// SPDX-License-Identifier: AGPL-3.0-only

package thin

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"
)

func writeFrame(conn net.Conn, blob []byte) {
	prefix := make([]byte, 4)
	binary.BigEndian.PutUint32(prefix, uint32(len(blob)))
	conn.Write(append(prefix, blob...))
}

func trySend(conn net.Conn, response *Response) {
	blob, err := cbor.Marshal(response)
	if err != nil {
		return
	}
	writeFrame(conn, blob)
}

func dialResult(t *testing.T, serve func(server net.Conn)) error {
	client, server := net.Pipe()
	tc := newHandshakeTestClient(t, client)
	go serve(server)
	err := tc.Dial()
	if err == nil {
		tc.Disconnect()
	}
	client.Close()
	server.Close()
	return err
}

func TestDialRejectsAGarbageFrame(t *testing.T) {
	err := dialResult(t, func(server net.Conn) {
		writeFrame(server, []byte("not cbor at all"))
	})
	require.Error(t, err)
}

func TestDialRejectsAnEmptyMessage(t *testing.T) {
	err := dialResult(t, func(server net.Conn) {
		writeFrame(server, []byte{0xa0})
		writeFrame(server, []byte{0xa0})
		writeFrame(server, []byte{0xa0})
		server.Close()
	})
	require.Error(t, err)
}

func TestDialRejectsAnOversizedFrame(t *testing.T) {
	err := dialResult(t, func(server net.Conn) {
		prefix := make([]byte, 4)
		binary.BigEndian.PutUint32(prefix, MaxMessageSize+1)
		server.Write(prefix)
	})
	require.Error(t, err)
}

func TestDialRejectsAConnectionStatusWithoutGeometry(t *testing.T) {
	err := dialResult(t, func(server net.Conn) {
		trySend(server, &Response{
			ConnectionStatusEvent: &ConnectionStatusEvent{IsConnected: true},
		})
	})
	require.Error(t, err)
}

func TestDialRejectsAClosedConnection(t *testing.T) {
	err := dialResult(t, func(server net.Conn) {
		server.Close()
	})
	require.Error(t, err)
}

func TestDialRejectsAShutdownDuringTheHandshake(t *testing.T) {
	sphinxGeo, pigeonGeo := newTestGeometries()
	err := dialResult(t, func(server net.Conn) {
		trySend(server, &Response{
			ConnectionStatusEvent: &ConnectionStatusEvent{
				IsConnected: true, SphinxGeometry: sphinxGeo, PigeonholeGeometry: pigeonGeo,
			},
		})
		trySend(server, pkiDocResponse(t, 500))
		if _, err := readRequest(server); err != nil {
			return
		}
		for i := 0; i < maxHandshakeMessages; i++ {
			trySend(server, &Response{ShutdownEvent: &ShutdownEvent{}})
		}
	})
	require.Error(t, err)
}

func TestDialRejectsAPKIDocumentWithAGarbagePayload(t *testing.T) {
	sphinxGeo, pigeonGeo := newTestGeometries()
	err := dialResult(t, func(server net.Conn) {
		trySend(server, &Response{
			ConnectionStatusEvent: &ConnectionStatusEvent{
				IsConnected: true, SphinxGeometry: sphinxGeo, PigeonholeGeometry: pigeonGeo,
			},
		})
		trySend(server, &Response{
			NewPKIDocumentEvent: &NewPKIDocumentEvent{Payload: []byte("not a document")},
		})
		if _, err := readRequest(server); err != nil {
			return
		}
		time.Sleep(10 * time.Millisecond)
		server.Close()
	})
	require.Error(t, err)
}

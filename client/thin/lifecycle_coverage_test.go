// SPDX-License-Identifier: AGPL-3.0-only

package thin

import (
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/client/config"
	"github.com/katzenpost/katzenpost/client/thin/transport"
	clienttransport "github.com/katzenpost/katzenpost/client/transport"
)

func TestValidateLoadedConfigRejectsWhatItMust(t *testing.T) {
	require.Error(t, validateLoadedConfig(&Config{}))
	require.Error(t, validateLoadedConfig(&Config{Dial: &transport.DialConfig{}}))
	require.Error(t, validateLoadedConfig(&Config{Dial: &transport.DialConfig{
		Unix: &transport.UnixDialConfig{Address: "@katzenpost"},
		Tcp:  &transport.TcpDialConfig{Address: "127.0.0.1:1", Network: "tcp"},
	}}))
	require.NoError(t, validateLoadedConfig(&Config{Dial: &transport.DialConfig{
		Unix: &transport.UnixDialConfig{Address: "@katzenpost"},
	}}))
}

func TestNewThinClientBuildsAClientAndRejectsABadLogLevel(t *testing.T) {
	cfg := &Config{Dial: &transport.DialConfig{Unix: &transport.UnixDialConfig{Address: "@katzenpost"}}}
	tc := NewThinClient(cfg, &config.Logging{Level: "DEBUG"})
	require.NotNil(t, tc)
	require.NotEqual(t, [16]byte{}, tc.instanceToken)
	require.Panics(t, func() { NewThinClient(cfg, &config.Logging{Level: "LOUD"}) })
}

func TestFromConfigCoversEveryTransport(t *testing.T) {
	unix := FromConfig(&config.Config{Listen: &clienttransport.ListenConfig{Unix: &clienttransport.UnixListenConfig{Address: "@katzenpost"}}})
	require.NotNil(t, unix.Dial.Unix)
	tcp := FromConfig(&config.Config{Listen: &clienttransport.ListenConfig{Tcp: &clienttransport.TcpListenConfig{Address: "127.0.0.1:1", Network: "tcp"}}})
	require.NotNil(t, tcp.Dial.Tcp)
	ws := FromConfig(&config.Config{Listen: &clienttransport.ListenConfig{Ws: &clienttransport.WsListenConfig{Address: "ws://127.0.0.1:1"}}})
	require.NotNil(t, ws.Dial.Ws)
	require.Panics(t, func() { FromConfig(&config.Config{}) })
	require.Panics(t, func() { FromConfig(&config.Config{Listen: &clienttransport.ListenConfig{}}) })
}

func TestDialReportsATransportFailure(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	address := listener.Addr().String()
	require.NoError(t, listener.Close())

	tc := newHandshakeTestClient(t, nil)
	tc.conn = nil
	tc.cfg = &Config{Dial: &transport.DialConfig{Tcp: &transport.TcpDialConfig{Address: address, Network: "tcp"}}}
	require.Error(t, tc.Dial())
}

func lcScriptedDaemon(t *testing.T, script func(conn net.Conn), served chan<- struct{}) string {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { listener.Close() })
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		script(conn)
		close(served)
		conn.Close()
	}()
	return listener.Addr().String()
}

func lcReconnectClient(t *testing.T, address string) *ThinClient {
	tc := newHandshakeTestClient(t, nil)
	tc.conn = nil
	tc.cfg = &Config{Dial: &transport.DialConfig{Tcp: &transport.TcpDialConfig{Address: address, Network: "tcp"}}}
	return tc
}

func lcStatusResponse() *Response {
	sphinxGeo, pigeonGeo := newTestGeometries()
	return &Response{ConnectionStatusEvent: &ConnectionStatusEvent{
		IsConnected: true, SphinxGeometry: sphinxGeo, PigeonholeGeometry: pigeonGeo,
	}}
}

func lcRedialGivesUpAfter(t *testing.T, script func(conn net.Conn)) {
	served := make(chan struct{})
	address := lcScriptedDaemon(t, script, served)
	tc := lcReconnectClient(t, address)
	go func() {
		<-served
		tc.Halt()
	}()
	require.False(t, tc.redial())
}

func TestRedialSurvivesAReadFailureOnTheStatusMessage(t *testing.T) {
	lcRedialGivesUpAfter(t, func(conn net.Conn) {})
}

func TestRedialSurvivesTheWrongFirstMessage(t *testing.T) {
	lcRedialGivesUpAfter(t, func(conn net.Conn) {
		trySend(conn, pkiDocResponse(t, 600))
	})
}

func TestRedialSurvivesAReadFailureOnThePKIDocument(t *testing.T) {
	lcRedialGivesUpAfter(t, func(conn net.Conn) {
		trySend(conn, lcStatusResponse())
	})
}

func TestRedialSurvivesTheWrongSecondMessage(t *testing.T) {
	lcRedialGivesUpAfter(t, func(conn net.Conn) {
		trySend(conn, lcStatusResponse())
		trySend(conn, &Response{SessionTokenReply: &SessionTokenReply{}})
	})
}

func TestRedialSurvivesAReadFailureOnTheSessionTokenReply(t *testing.T) {
	lcRedialGivesUpAfter(t, func(conn net.Conn) {
		trySend(conn, lcStatusResponse())
		trySend(conn, pkiDocResponse(t, 601))
		readRequest(conn)
	})
}

func TestRedialSurvivesTheWrongThirdMessage(t *testing.T) {
	lcRedialGivesUpAfter(t, func(conn net.Conn) {
		trySend(conn, lcStatusResponse())
		trySend(conn, pkiDocResponse(t, 602))
		readRequest(conn)
		trySend(conn, lcStatusResponse())
	})
}

func TestRedialReconnects(t *testing.T) {
	served := make(chan struct{})
	address := lcScriptedDaemon(t, func(conn net.Conn) {
		trySend(conn, lcStatusResponse())
		trySend(conn, pkiDocResponse(t, 603))
		readRequest(conn)
		trySend(conn, &Response{SessionTokenReply: &SessionTokenReply{Resumed: true}})
	}, served)
	tc := lcReconnectClient(t, address)
	tc.inFlightResends.Store([MessageIDLength]byte{1}, &Request{SendMessage: &SendMessage{Payload: []byte("replay")}})
	require.True(t, tc.redial())
	<-served
	tc.Halt()
}

func TestRedialStopsWhenHalted(t *testing.T) {
	tc := lcReconnectClient(t, "127.0.0.1:1")
	tc.Halt()
	require.False(t, tc.redial())
}

type lcShortWriteConn struct {
	net.Conn
}

func (c lcShortWriteConn) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	return 1, nil
}

func TestWriteMessageRejectsAPayloadWithoutGeometry(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	tc := newHandshakeTestClient(t, client)
	tc.sphinxGeo = nil
	err := tc.writeMessage(&Request{SendMessage: &SendMessage{Payload: []byte("payload")}})
	require.Error(t, err)
}

func TestWriteMessageRejectsAPayloadOverTheGeometry(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	tc := newHandshakeTestClient(t, client)
	oversized := make([]byte, tc.sphinxGeo.UserForwardPayloadLength+1)
	require.Error(t, tc.writeMessage(&Request{SendMessage: &SendMessage{Payload: oversized}}))
}

func TestWriteMessageReportsAShortWrite(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	tc := newHandshakeTestClient(t, lcShortWriteConn{client})
	err := tc.writeMessage(&Request{ThinClose: &ThinClose{}})
	require.Error(t, err)
}

func TestReadMessageReportsATruncatedBody(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	tc := newHandshakeTestClient(t, client)
	go func() {
		prefix := make([]byte, 4)
		binary.BigEndian.PutUint32(prefix, 64)
		server.Write(prefix)
		server.Write([]byte("short"))
		server.Close()
	}()
	_, err := tc.readMessage()
	require.Error(t, err)
}

func TestReadUntilDisconnectKeepsReadingAfterAnOversizedFrame(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	tc := newHandshakeTestClient(t, client)
	go func() {
		prefix := make([]byte, 4)
		binary.BigEndian.PutUint32(prefix, MaxMessageSize+1)
		server.Write(prefix)
		server.Close()
	}()
	err, graceful := tc.readUntilDisconnect()
	require.Error(t, err)
	require.False(t, graceful)
}

func TestReadUntilDisconnectTreatsShutdownAsGraceful(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	tc := newHandshakeTestClient(t, client)
	go func() {
		trySend(server, &Response{ShutdownEvent: &ShutdownEvent{}})
		server.Close()
	}()
	_, graceful := tc.readUntilDisconnect()
	require.True(t, graceful)
}

func TestReadUntilDisconnectStopsWhenHalted(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	tc := newHandshakeTestClient(t, client)
	tc.Halt()
	err, graceful := tc.readUntilDisconnect()
	require.NoError(t, err)
	require.False(t, graceful)
}

func TestReplayInFlightResendsReportsAWriteFailure(t *testing.T) {
	client, server := net.Pipe()
	server.Close()
	client.Close()
	tc := newHandshakeTestClient(t, client)
	tc.inFlightResends.Store([MessageIDLength]byte{2}, &Request{ThinClose: &ThinClose{}})
	tc.replayInFlightResends()
}

func TestEventSinkWorkerStopsWhileADrainIsBlocked(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	tc := newHandshakeTestClient(t, client)
	drain := make(chan Event)
	tc.Go(tc.eventSinkWorker)
	tc.drainAdd <- drain
	tc.eventSink <- &ConnectionStatusEvent{IsConnected: true}
	time.Sleep(100 * time.Millisecond)
	tc.Halt()
	time.Sleep(100 * time.Millisecond)
}

func TestDialReportsAFailureReadingThePKIDocument(t *testing.T) {
	sphinxGeo, pigeonGeo := newTestGeometries()
	err := dialResult(t, func(server net.Conn) {
		trySend(server, &Response{ConnectionStatusEvent: &ConnectionStatusEvent{
			IsConnected: true, SphinxGeometry: sphinxGeo, PigeonholeGeometry: pigeonGeo,
		}})
		server.Close()
	})
	require.Error(t, err)
}

func TestDialReportsAFailureSendingTheSessionToken(t *testing.T) {
	sphinxGeo, pigeonGeo := newTestGeometries()
	client, server := net.Pipe()
	tc := newHandshakeTestClient(t, client)
	go func() {
		trySend(server, &Response{ConnectionStatusEvent: &ConnectionStatusEvent{
			IsConnected: true, SphinxGeometry: sphinxGeo, PigeonholeGeometry: pigeonGeo,
		}})
		trySend(server, pkiDocResponse(t, 700))
		client.Close()
	}()
	require.Error(t, tc.Dial())
	server.Close()
}

func TestReadUntilDisconnectStopsWhenDispatchIsHalted(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()
	defer server.Close()
	tc := newHandshakeTestClient(t, client)
	tc.eventSink = make(chan Event)
	go func() {
		trySend(server, &Response{MessageSentEvent: &MessageSentEvent{}})
		time.Sleep(50 * time.Millisecond)
		tc.Halt()
	}()
	err, graceful := tc.readUntilDisconnect()
	require.NoError(t, err)
	require.False(t, graceful)
}

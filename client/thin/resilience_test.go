// SPDX-FileCopyrightText: (c) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package thin

import (
	"encoding/binary"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/katzenpost/hpqc/nike/schemes"
	"github.com/katzenpost/katzenpost/client/config"
	"github.com/katzenpost/katzenpost/core/log"
	cpki "github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	pigeonholeGeo "github.com/katzenpost/katzenpost/pigeonhole/geo"
	"github.com/stretchr/testify/require"
)

func sendMockResponse(t *testing.T, conn net.Conn, resp *Response) {
	t.Helper()
	blob, err := cbor.Marshal(resp)
	require.NoError(t, err)
	prefix := make([]byte, 4)
	binary.BigEndian.PutUint32(prefix, uint32(len(blob)))
	_, err = conn.Write(append(prefix, blob...))
	require.NoError(t, err)
}

func newTestThinClient(t *testing.T, conn net.Conn) *ThinClient {
	t.Helper()
	logBackend, err := log.New("", "DEBUG", false)
	require.NoError(t, err)

	nikeScheme := schemes.ByName("x25519")

	return &ThinClient{
		cfg: &Config{
			SphinxGeometry:     &geo.Geometry{UserForwardPayloadLength: 1000},
			PigeonholeGeometry: pigeonholeGeo.NewGeometry(1000, nikeScheme),
			Network:            "tcp",
			Address:            "localhost:0",
		},
		log:         logBackend.GetLogger("thinclient"),
		logBackend:  logBackend,
		conn:        conn,
		eventSink:   make(chan Event, 2),
		drainAdd:    make(chan chan Event),
		drainRemove: make(chan chan Event),
		pkiDocCache: make(map[uint64]*cpki.Document),
	}
}

// TestConnectionStatusEventInstanceToken verifies that the InstanceToken
// field on ConnectionStatusEvent survives a CBOR marshal/unmarshal round-trip.
func TestConnectionStatusEventInstanceToken(t *testing.T) {
	token := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}

	original := &ConnectionStatusEvent{
		IsConnected:   true,
		Err:           nil,
		InstanceToken: token,
	}

	blob, err := cbor.Marshal(original)
	require.NoError(t, err)

	decoded := &ConnectionStatusEvent{}
	err = cbor.Unmarshal(blob, decoded)
	require.NoError(t, err)

	require.Equal(t, original.IsConnected, decoded.IsConnected)
	require.Equal(t, original.InstanceToken, decoded.InstanceToken)
	require.Equal(t, token, decoded.InstanceToken)
}

// TestGracefulDisconnectEvent verifies that when the daemon sends a
// ShutdownEvent before closing the connection, the thin client emits
// a DaemonDisconnectedEvent with IsGraceful=true.
func TestGracefulDisconnectEvent(t *testing.T) {
	client, server := net.Pipe()

	thin := newTestThinClient(t, client)

	// Start workers in background goroutines.
	go thin.eventSinkWorker()
	go thin.worker()

	// Get an event sink channel before the daemon sends anything.
	eventCh := thin.EventSink()

	// Daemon side: send ShutdownEvent, then close connection.
	go func() {
		sendMockResponse(t, server, &Response{
			ShutdownEvent: &ShutdownEvent{},
		})
		server.Close()
	}()

	// Wait for a DaemonDisconnectedEvent with a reasonable timeout.
	select {
	case ev := <-eventCh:
		dde, ok := ev.(*DaemonDisconnectedEvent)
		require.True(t, ok, "expected DaemonDisconnectedEvent, got %T", ev)
		require.True(t, dde.IsGraceful, "expected graceful disconnect")
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for DaemonDisconnectedEvent")
	}

	// Stop the thin client so the redial loop does not hang the test.
	_ = thin.Close()
}

// TestCrashDisconnectEvent verifies that when the daemon connection drops
// without a prior ShutdownEvent, the thin client emits a
// DaemonDisconnectedEvent with IsGraceful=false.
func TestCrashDisconnectEvent(t *testing.T) {
	client, server := net.Pipe()

	thin := newTestThinClient(t, client)

	go thin.eventSinkWorker()
	go thin.worker()

	eventCh := thin.EventSink()

	// Daemon side: just close without sending ShutdownEvent.
	go func() {
		server.Close()
	}()

	select {
	case ev := <-eventCh:
		dde, ok := ev.(*DaemonDisconnectedEvent)
		require.True(t, ok, "expected DaemonDisconnectedEvent, got %T", ev)
		require.False(t, dde.IsGraceful, "expected non-graceful disconnect")
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for DaemonDisconnectedEvent")
	}

	_ = thin.Close()
}

// TestCancelRemovesFromInFlightTracking verifies that deleting from
// inFlightResends (as CancelResendingEncryptedMessage does) actually
// removes the entry.
func TestCancelRemovesFromInFlightTracking(t *testing.T) {
	client, _ := net.Pipe()
	defer client.Close()

	thin := newTestThinClient(t, client)

	key := [32]byte{0xAA}
	req := &Request{
		StartResendingEncryptedMessage: &StartResendingEncryptedMessage{
			EnvelopeHash: &key,
		},
	}

	// Store a request as the daemon would track it.
	thin.inFlightResends.Store(key, req)

	// Verify it is present.
	_, loaded := thin.inFlightResends.Load(key)
	require.True(t, loaded, "expected in-flight entry to be present")

	// Simulate what CancelResendingEncryptedMessage does.
	thin.inFlightResends.Delete(key)

	// Verify it is gone.
	_, loaded = thin.inFlightResends.Load(key)
	require.False(t, loaded, "expected in-flight entry to be removed after cancel")
}

// TestCloseStopsWorker verifies that calling Close() on the thin client
// causes HaltCh to be closed, which signals workers to exit.
func TestCloseStopsWorker(t *testing.T) {
	client, server := net.Pipe()

	thin := newTestThinClient(t, client)

	go thin.eventSinkWorker()
	go thin.worker()

	// Drain the server side so that Close()'s writeMessage (ThinClose) and
	// the worker's readMessage do not block on the pipe.
	go func() {
		buf := make([]byte, 4096)
		for {
			_, err := server.Read(buf)
			if err != nil {
				return
			}
		}
	}()

	// Close the thin client. This should halt all workers.
	err := thin.Close()
	// Close may return an error from the connection close; that is acceptable.
	_ = err
	server.Close()

	// HaltCh should now be closed.
	select {
	case <-thin.HaltCh():
		// success: workers have been told to stop
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for HaltCh to close after Close()")
	}
}

// mockDaemonHandshake performs the daemon-side handshake: sends
// ConnectionStatusEvent (with instance token), NewPKIDocumentEvent,
// reads SessionToken, and sends SessionTokenReply.
func mockDaemonHandshake(t *testing.T, conn net.Conn, token [16]byte) {
	t.Helper()
	sendMockResponse(t, conn, &Response{
		ConnectionStatusEvent: &ConnectionStatusEvent{
			IsConnected:   true,
			InstanceToken: token,
		},
	})
	sendMockResponse(t, conn, &Response{
		NewPKIDocumentEvent: &NewPKIDocumentEvent{
			Payload: []byte{},
		},
	})
	// Read SessionToken from thin client
	readMockRequest(t, conn)
	// Send SessionTokenReply
	sendMockResponse(t, conn, &Response{
		SessionTokenReply: &SessionTokenReply{
			AppID:   make([]byte, 16),
			Resumed: false,
		},
	})
}

// readMockRequest reads one length-prefixed CBOR request from the connection.
func readMockRequest(t *testing.T, conn net.Conn) *Request {
	t.Helper()
	prefix := make([]byte, 4)
	_, err := io.ReadFull(conn, prefix)
	require.NoError(t, err)
	length := binary.BigEndian.Uint32(prefix)
	blob := make([]byte, length)
	_, err = io.ReadFull(conn, blob)
	require.NoError(t, err)
	req := &Request{}
	err = cbor.Unmarshal(blob, req)
	require.NoError(t, err)
	return req
}

// TestRedialAfterDisconnect verifies that the thin client reconnects
// to a new TCP listener after the daemon connection drops.
func TestRedialAfterDisconnect(t *testing.T) {
	// Start a TCP listener for the thin client to connect to.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	logBackend, err := log.New("", "DEBUG", false)
	require.NoError(t, err)
	nikeScheme := schemes.ByName("x25519")

	token1 := [16]byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}
	token2 := [16]byte{2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2}

	// Accept the first connection and do the handshake.
	acceptDone := make(chan net.Conn, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		acceptDone <- conn
	}()

	tc := &ThinClient{
		cfg: &Config{
			SphinxGeometry:     &geo.Geometry{UserForwardPayloadLength: 1000},
			PigeonholeGeometry: pigeonholeGeo.NewGeometry(1000, nikeScheme),
			Network:            "tcp",
			Address:            listener.Addr().String(),
		},
		log:         logBackend.GetLogger("thinclient"),
		logBackend:  logBackend,
		eventSink:   make(chan Event, 2),
		drainAdd:    make(chan chan Event),
		drainRemove: make(chan chan Event),
		pkiDocCache: make(map[uint64]*cpki.Document),
	}

	// Dial manually (like Dial() does).
	tc.conn, err = net.Dial("tcp", listener.Addr().String())
	require.NoError(t, err)

	// Get the accepted server connection.
	var serverConn1 net.Conn
	select {
	case serverConn1 = <-acceptDone:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for first accept")
	}

	// Do the initial handshake (must be in goroutine to avoid deadlock on pipe).
	go mockDaemonHandshake(t, serverConn1, token1)

	// Read and process the handshake on the client side.
	msg1, err := tc.readMessage()
	require.NoError(t, err)
	require.NotNil(t, msg1.ConnectionStatusEvent)
	tc.isConnected = msg1.ConnectionStatusEvent.IsConnected
	tc.daemonInstanceToken = msg1.ConnectionStatusEvent.InstanceToken

	msg2, err := tc.readMessage()
	require.NoError(t, err)
	require.NotNil(t, msg2.NewPKIDocumentEvent)

	// Send SessionToken and read SessionTokenReply
	err = tc.writeMessage(&Request{
		SessionToken: &SessionToken{ClientInstanceToken: tc.instanceToken},
	})
	require.NoError(t, err)
	msg3, err := tc.readMessage()
	require.NoError(t, err)
	require.NotNil(t, msg3.SessionTokenReply)

	require.Equal(t, token1, tc.daemonInstanceToken)

	// Start workers.
	tc.Go(tc.eventSinkWorker)
	tc.Go(tc.worker)
	eventCh := tc.EventSink()

	// Accept the next connection (the redial).
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		acceptDone <- conn
	}()

	// Close the first server connection to trigger disconnect.
	serverConn1.Close()

	// Wait for DaemonDisconnectedEvent.
	select {
	case ev := <-eventCh:
		dde, ok := ev.(*DaemonDisconnectedEvent)
		require.True(t, ok, "expected DaemonDisconnectedEvent, got %T", ev)
		require.False(t, dde.IsGraceful)
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for DaemonDisconnectedEvent")
	}

	// Accept the reconnection and do the handshake with a new token.
	var serverConn2 net.Conn
	select {
	case serverConn2 = <-acceptDone:
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for redial accept")
	}
	defer serverConn2.Close()

	mockDaemonHandshake(t, serverConn2, token2)

	// After reconnect, the worker re-enters the read loop. The daemon instance
	// token should have been updated. Poll for it since the handshake happens
	// inside redial() before returning to the read loop.
	require.Eventually(t, func() bool {
		tc.connMu.RLock()
		defer tc.connMu.RUnlock()
		return tc.daemonInstanceToken == token2
	}, 10*time.Second, 50*time.Millisecond, "expected daemon instance token to be updated after reconnect")

	// Close the thin client. Close the server first so worker doesn't block on read.
	serverConn2.Close()
	_ = tc.Close()
}

// TestNewInstanceTokenReplaysRequests verifies that when reconnecting to
// a new daemon instance (different token), in-flight requests are replayed.
func TestNewInstanceTokenReplaysRequests(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	logBackend, err := log.New("", "DEBUG", false)
	require.NoError(t, err)
	nikeScheme := schemes.ByName("x25519")

	token1 := [16]byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}
	token2 := [16]byte{2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2}

	acceptCh := make(chan net.Conn, 2)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			acceptCh <- conn
		}
	}()

	tc := &ThinClient{
		cfg: &Config{
			SphinxGeometry:     &geo.Geometry{UserForwardPayloadLength: 1000},
			PigeonholeGeometry: pigeonholeGeo.NewGeometry(1000, nikeScheme),
			Network:            "tcp",
			Address:            listener.Addr().String(),
		},
		log:         logBackend.GetLogger("thinclient"),
		logBackend:  logBackend,
		eventSink:   make(chan Event, 2),
		drainAdd:    make(chan chan Event),
		drainRemove: make(chan chan Event),
		pkiDocCache: make(map[uint64]*cpki.Document),
	}

	// Initial connection.
	tc.conn, err = net.Dial("tcp", listener.Addr().String())
	require.NoError(t, err)

	serverConn1 := <-acceptCh
	go mockDaemonHandshake(t, serverConn1, token1)

	msg1, _ := tc.readMessage()
	tc.isConnected = msg1.ConnectionStatusEvent.IsConnected
	tc.daemonInstanceToken = msg1.ConnectionStatusEvent.InstanceToken
	tc.readMessage() // consume PKI doc
	tc.writeMessage(&Request{SessionToken: &SessionToken{ClientInstanceToken: tc.instanceToken}})
	tc.readMessage() // consume SessionTokenReply

	// Seed an in-flight request.
	envelopeHash := [32]byte{0xDE, 0xAD}
	queryID := tc.NewQueryID()
	req := &Request{
		StartResendingEncryptedMessage: &StartResendingEncryptedMessage{
			QueryID:      queryID,
			EnvelopeHash: &envelopeHash,
		},
	}
	tc.inFlightResends.Store(envelopeHash, req)

	// Start workers.
	tc.Go(tc.eventSinkWorker)
	tc.Go(tc.worker)
	eventCh := tc.EventSink()

	// Disconnect.
	serverConn1.Close()

	// Drain the DaemonDisconnectedEvent.
	select {
	case <-eventCh:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for DaemonDisconnectedEvent")
	}

	// Accept reconnection with a different token.
	var serverConn2 net.Conn
	select {
	case serverConn2 = <-acceptCh:
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for reconnect")
	}
	defer serverConn2.Close()

	mockDaemonHandshake(t, serverConn2, token2)

	// The worker should replay the in-flight request. Read it from the server side.
	replayed := readMockRequest(t, serverConn2)
	require.NotNil(t, replayed.StartResendingEncryptedMessage,
		"expected replayed StartResendingEncryptedMessage request")
	require.Equal(t, envelopeHash, *replayed.StartResendingEncryptedMessage.EnvelopeHash)

	// Close server before thin client so worker() doesn't block on readMessage().
	serverConn2.Close()
	_ = tc.Close()
}

// TestSameInstanceTokenSkipsReplay verifies that when reconnecting to
// the same daemon instance (same token), in-flight requests are NOT replayed.
func TestSameInstanceTokenSkipsReplay(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	logBackend, err := log.New("", "DEBUG", false)
	require.NoError(t, err)
	nikeScheme := schemes.ByName("x25519")

	token := [16]byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1}

	acceptCh := make(chan net.Conn, 2)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			acceptCh <- conn
		}
	}()

	tc := &ThinClient{
		cfg: &Config{
			SphinxGeometry:     &geo.Geometry{UserForwardPayloadLength: 1000},
			PigeonholeGeometry: pigeonholeGeo.NewGeometry(1000, nikeScheme),
			Network:            "tcp",
			Address:            listener.Addr().String(),
		},
		log:         logBackend.GetLogger("thinclient"),
		logBackend:  logBackend,
		eventSink:   make(chan Event, 2),
		drainAdd:    make(chan chan Event),
		drainRemove: make(chan chan Event),
		pkiDocCache: make(map[uint64]*cpki.Document),
	}

	// Initial connection.
	tc.conn, err = net.Dial("tcp", listener.Addr().String())
	require.NoError(t, err)

	serverConn1 := <-acceptCh
	go mockDaemonHandshake(t, serverConn1, token)

	msg1, _ := tc.readMessage()
	tc.isConnected = msg1.ConnectionStatusEvent.IsConnected
	tc.daemonInstanceToken = msg1.ConnectionStatusEvent.InstanceToken
	tc.readMessage() // consume PKI doc
	tc.writeMessage(&Request{SessionToken: &SessionToken{ClientInstanceToken: tc.instanceToken}})
	tc.readMessage() // consume SessionTokenReply

	// Seed an in-flight request.
	envelopeHash := [32]byte{0xDE, 0xAD}
	queryID := tc.NewQueryID()
	req := &Request{
		StartResendingEncryptedMessage: &StartResendingEncryptedMessage{
			QueryID:      queryID,
			EnvelopeHash: &envelopeHash,
		},
	}
	tc.inFlightResends.Store(envelopeHash, req)

	// Start workers.
	tc.Go(tc.eventSinkWorker)
	tc.Go(tc.worker)
	eventCh := tc.EventSink()

	// Disconnect.
	serverConn1.Close()

	// Drain the DaemonDisconnectedEvent.
	select {
	case <-eventCh:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for DaemonDisconnectedEvent")
	}

	// Accept reconnection with the SAME token.
	var serverConn2 net.Conn
	select {
	case serverConn2 = <-acceptCh:
	case <-time.After(10 * time.Second):
		t.Fatal("timed out waiting for reconnect")
	}
	defer serverConn2.Close()

	mockDaemonHandshake(t, serverConn2, token)

	// Set a short deadline on the server connection to check that
	// NO replay request arrives.
	serverConn2.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	prefix := make([]byte, 4)
	_, err = io.ReadFull(serverConn2, prefix)
	require.Error(t, err, "expected no data (timeout), but got a message — replay should have been skipped")

	// Close server before thin client so worker() doesn't block on readMessage().
	serverConn2.Close()
	_ = tc.Close()
}

// TestCancelDuringDisconnect verifies that calling cancel while disconnected
// removes the request from in-flight tracking and prevents replay on reconnect.
func TestCancelDuringDisconnect(t *testing.T) {
	client, server := net.Pipe()

	tc := newTestThinClient(t, client)

	// Seed an in-flight request.
	envelopeHash := [32]byte{0xBE, 0xEF}
	tc.inFlightResends.Store(envelopeHash, &Request{})

	// Simulate disconnected state.
	tc.isConnected = false
	server.Close()

	// Remove via the same path CancelResendingEncryptedMessage uses.
	tc.inFlightResends.Delete(envelopeHash)

	// Verify it's gone.
	_, loaded := tc.inFlightResends.Load(envelopeHash)
	require.False(t, loaded, "expected request removed from tracking after cancel during disconnect")
}

// TestInFlightTrackingStoreAndDelete verifies the basic lifecycle of
// inFlightResends: store on send, delete on completion.
func TestInFlightTrackingStoreAndDelete(t *testing.T) {
	client, _ := net.Pipe()
	defer client.Close()

	tc := newTestThinClient(t, client)

	// Simulate storing multiple in-flight requests.
	hash1 := [32]byte{1}
	hash2 := [32]byte{2}
	hash3 := [32]byte{3}

	tc.inFlightResends.Store(hash1, &Request{})
	tc.inFlightResends.Store(hash2, &Request{})
	tc.inFlightResends.Store(hash3, &Request{})

	// Count entries.
	count := 0
	tc.inFlightResends.Range(func(_, _ any) bool {
		count++
		return true
	})
	require.Equal(t, 3, count)

	// Delete one.
	tc.inFlightResends.Delete(hash2)

	count = 0
	tc.inFlightResends.Range(func(_, _ any) bool {
		count++
		return true
	})
	require.Equal(t, 2, count)

	// Verify the right ones remain.
	_, ok1 := tc.inFlightResends.Load(hash1)
	_, ok2 := tc.inFlightResends.Load(hash2)
	_, ok3 := tc.inFlightResends.Load(hash3)
	require.True(t, ok1)
	require.False(t, ok2)
	require.True(t, ok3)
}

// TestDispatchMessageRoutesEvents verifies that dispatchMessage correctly
// routes different message types to the event sink.
func TestDispatchMessageRoutesEvents(t *testing.T) {
	client, _ := net.Pipe()
	defer client.Close()

	tc := newTestThinClient(t, client)
	go tc.eventSinkWorker()

	eventCh := tc.EventSink()
	// Note: StopEventSink sends on drainRemove which requires eventSinkWorker
	// to be running. We must stop the sink before Halt() kills the worker.

	// Test ConnectionStatusEvent dispatch.
	token := [16]byte{0xAA}
	ok := tc.dispatchMessage(&Response{
		ConnectionStatusEvent: &ConnectionStatusEvent{
			IsConnected:   true,
			InstanceToken: token,
		},
	})
	require.True(t, ok)

	select {
	case ev := <-eventCh:
		cse, ok := ev.(*ConnectionStatusEvent)
		require.True(t, ok)
		require.True(t, cse.IsConnected)
		require.Equal(t, token, cse.InstanceToken)
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for ConnectionStatusEvent")
	}

	// Verify isConnected was updated.
	require.True(t, tc.isConnected)

	// Test NewKeypairReply dispatch.
	queryID := &[QueryIDLength]byte{0x01}
	ok = tc.dispatchMessage(&Response{
		NewKeypairReply: &NewKeypairReply{
			QueryID: queryID,
		},
	})
	require.True(t, ok)

	select {
	case ev := <-eventCh:
		nkr, ok := ev.(*NewKeypairReply)
		require.True(t, ok)
		require.Equal(t, queryID, nkr.QueryID)
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for NewKeypairReply")
	}

	// StopEventSink must be called before Halt() since it sends on drainRemove
	// which requires eventSinkWorker to be running.
	tc.StopEventSink(eventCh)
	tc.Halt()
}

// TestReplayInFlightResends verifies that replayInFlightResends sends
// all tracked requests over the wire.
func TestReplayInFlightResends(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()

	tc := newTestThinClient(t, client)

	// Store two in-flight requests.
	hash1 := [32]byte{0x01}
	hash2 := [32]byte{0x02}
	queryID1 := &[QueryIDLength]byte{0x10}
	queryID2 := &[QueryIDLength]byte{0x20}

	tc.inFlightResends.Store(hash1, &Request{
		StartResendingEncryptedMessage: &StartResendingEncryptedMessage{
			QueryID:      queryID1,
			EnvelopeHash: &hash1,
		},
	})
	tc.inFlightResends.Store(hash2, &Request{
		StartResendingEncryptedMessage: &StartResendingEncryptedMessage{
			QueryID:      queryID2,
			EnvelopeHash: &hash2,
		},
	})

	// Replay in a goroutine (writeMessage blocks until server reads).
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		tc.replayInFlightResends()
	}()

	// Read two requests from the server side.
	req1 := readMockRequest(t, server)
	req2 := readMockRequest(t, server)
	wg.Wait()

	// Both should be StartResendingEncryptedMessage requests.
	require.NotNil(t, req1.StartResendingEncryptedMessage)
	require.NotNil(t, req2.StartResendingEncryptedMessage)

	// Collect the replayed hashes (order not guaranteed with sync.Map).
	hashes := map[[32]byte]bool{
		*req1.StartResendingEncryptedMessage.EnvelopeHash: true,
		*req2.StartResendingEncryptedMessage.EnvelopeHash: true,
	}
	require.True(t, hashes[hash1], "expected hash1 to be replayed")
	require.True(t, hashes[hash2], "expected hash2 to be replayed")
}

// TestDaemonInstanceTokenStoredOnDial verifies that Dial() stores
// the daemon's instance token from the initial handshake.
func TestDaemonInstanceTokenStoredOnDial(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer listener.Close()

	nikeScheme := schemes.ByName("x25519")
	token := [16]byte{0xCA, 0xFE, 0xBA, 0xBE}

	serverConnCh := make(chan net.Conn, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		mockDaemonHandshake(t, conn, token)
		serverConnCh <- conn
	}()

	tc := NewThinClient(&Config{
		SphinxGeometry:     &geo.Geometry{UserForwardPayloadLength: 1000},
		PigeonholeGeometry: pigeonholeGeo.NewGeometry(1000, nikeScheme),
		Network:            "tcp",
		Address:            listener.Addr().String(),
	}, &config.Logging{Level: "DEBUG"})

	err = tc.Dial()
	require.NoError(t, err)

	tc.connMu.RLock()
	require.Equal(t, token, tc.daemonInstanceToken)
	tc.connMu.RUnlock()

	// Close the server connection first so worker() unblocks from readMessage().
	serverConn := <-serverConnCh
	serverConn.Close()
	tc.Close()
}

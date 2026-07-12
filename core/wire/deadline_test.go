// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package wire

import (
	"context"
	"crypto/rand"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	ecdh "github.com/katzenpost/hpqc/nike/x25519"

	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/katzenpost/katzenpost/core/wire/commands"
)

// deadlineTestConfigs returns a fresh Alice (initiator) and Bob (responder)
// SessionConfig pair that authenticate each other. Callers set the timeout
// fields before establishing the pair.
func deadlineTestConfigs(t *testing.T) (alice, bob *SessionConfig) {
	t.Helper()
	aPub, aPriv, err := testingScheme.GenerateKeyPair()
	require.NoError(t, err)
	bPub, bPriv, err := testingScheme.GenerateKeyPair()
	require.NoError(t, err)
	credsA := &PeerCredentials{AdditionalData: []byte("alice"), PublicKey: aPub}
	credsB := &PeerCredentials{AdditionalData: []byte("bob"), PublicKey: bPub}
	g := geo.GeometryFromUserForwardPayloadLength(ecdh.Scheme(rand.Reader), 3000, true, 5)
	alice = &SessionConfig{
		KEMScheme:         testingScheme,
		Geometry:          g,
		Authenticator:     &stubAuthenticator{creds: credsB},
		AdditionalData:    credsA.AdditionalData,
		AuthenticationKey: aPriv,
		RandomReader:      rand.Reader,
	}
	bob = &SessionConfig{
		KEMScheme:         testingScheme,
		Geometry:          g,
		Authenticator:     &stubAuthenticator{creds: credsA},
		AdditionalData:    credsB.AdditionalData,
		AuthenticationKey: bPriv,
		RandomReader:      rand.Reader,
	}
	return alice, bob
}

func establishTestPair(t *testing.T, alice, bob *SessionConfig) (sAlice, sBob *Session, connAlice, connBob net.Conn) {
	t.Helper()
	var err error
	sAlice, err = NewSession(alice, true)
	require.NoError(t, err)
	sBob, err = NewSession(bob, false)
	require.NoError(t, err)
	connAlice, connBob = net.Pipe()
	ea := make(chan error, 1)
	eb := make(chan error, 1)
	go func() { ea <- sAlice.Initialize(context.Background(), connAlice) }()
	go func() { eb <- sBob.Initialize(context.Background(), connBob) }()
	require.NoError(t, <-ea)
	require.NoError(t, <-eb)
	return sAlice, sBob, connAlice, connBob
}

// TestRecvCommandBoundedByReadTimeout proves that a RecvCommand called with
// context.Background() still returns (with an error) once ReadTimeout elapses
// when the peer sends nothing: no caller can wedge forever on a silent peer.
func TestRecvCommandBoundedByReadTimeout(t *testing.T) {
	t.Parallel()
	alice, bob := deadlineTestConfigs(t)
	bob.ReadTimeout = 200 * time.Millisecond
	sAlice, sBob, connAlice, connBob := establishTestPair(t, alice, bob)
	defer sAlice.Close()
	defer sBob.Close()
	defer connAlice.Close()
	defer connBob.Close()

	done := make(chan error, 1)
	go func() { _, err := sBob.RecvCommand(context.Background()); done <- err }()
	select {
	case err := <-done:
		require.Error(t, err, "RecvCommand must fail once ReadTimeout elapses on a silent peer")
	case <-time.After(5 * time.Second):
		t.Fatal("RecvCommand did not return: the read is unbounded")
	}
}

// TestSendCommandBoundedByWriteTimeout proves that SendCommand returns (with an
// error) once WriteTimeout elapses when the peer never reads. net.Pipe is
// unbuffered, so the write blocks until the timeout fires.
func TestSendCommandBoundedByWriteTimeout(t *testing.T) {
	t.Parallel()
	alice, bob := deadlineTestConfigs(t)
	alice.WriteTimeout = 200 * time.Millisecond
	sAlice, sBob, connAlice, connBob := establishTestPair(t, alice, bob)
	defer sAlice.Close()
	defer sBob.Close()
	defer connAlice.Close()
	defer connBob.Close()

	cmd := &commands.SendPacket{SphinxPacket: []byte("payload"), Cmds: sAlice.GetCommands()}
	done := make(chan error, 1)
	go func() { done <- sAlice.SendCommand(context.Background(), cmd) }()
	select {
	case err := <-done:
		require.Error(t, err, "SendCommand must fail once WriteTimeout elapses when the peer is not reading")
	case <-time.After(5 * time.Second):
		t.Fatal("SendCommand did not return: the write is unbounded")
	}
}

// TestRecvCommandCancelledByContext proves that cancelling the context
// interrupts a blocked RecvCommand promptly, even when the deadline is far away.
func TestRecvCommandCancelledByContext(t *testing.T) {
	t.Parallel()
	alice, bob := deadlineTestConfigs(t)
	bob.ReadTimeout = 30 * time.Second // far away: cancellation must win
	sAlice, sBob, connAlice, connBob := establishTestPair(t, alice, bob)
	defer sAlice.Close()
	defer sBob.Close()
	defer connAlice.Close()
	defer connBob.Close()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { _, err := sBob.RecvCommand(ctx); done <- err }()
	time.Sleep(100 * time.Millisecond)
	cancel()
	select {
	case err := <-done:
		require.Error(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("cancelled RecvCommand did not return")
	}
}

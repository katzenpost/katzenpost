// SPDX-FileCopyrightText: Copyright (C) 2025 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package wire

import (
	"crypto/rand"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	ecdh "github.com/katzenpost/hpqc/nike/x25519"

	"github.com/katzenpost/katzenpost/core/sphinx/geo"
)

// TestHandshakeErrorWrapping_EOF tests that EOF errors during handshake
// are properly wrapped with HandshakeError containing useful context.
func TestHandshakeErrorWrapping_EOF(t *testing.T) {
	require := require.New(t)

	scheme := testingScheme
	authKEMKeyAlicePub, authKEMKeyAlice, err := scheme.GenerateKeyPair()
	require.NoError(err)

	credsAlice := &PeerCredentials{
		AdditionalData: []byte("alice@example.com"),
		PublicKey:      authKEMKeyAlicePub,
	}

	authKEMKeyBobPub, _, err := scheme.GenerateKeyPair()
	require.NoError(err)

	credsBob := &PeerCredentials{
		AdditionalData: []byte("bob@example.com"),
		PublicKey:      authKEMKeyBobPub,
	}

	nike := ecdh.Scheme(rand.Reader)
	geometry := geo.GeometryFromUserForwardPayloadLength(nike, 3000, true, 5)

	// Alice's session setup (initiator)
	cfgAlice := &SessionConfig{
		KEMScheme:         testingScheme,
		Geometry:          geometry,
		Authenticator:     &stubAuthenticator{creds: credsBob},
		AdditionalData:    credsAlice.AdditionalData,
		AuthenticationKey: authKEMKeyAlice,
		RandomReader:      rand.Reader,
	}
	sAlice, err := NewSession(cfgAlice, true)
	require.NoError(err, "Alice NewSession()")

	// Create a pipe connection
	connAlice, connBob := net.Pipe()

	var wg sync.WaitGroup
	var handshakeErr error

	wg.Add(1)
	go func() {
		defer wg.Done()
		defer connAlice.Close()

		// Try to initialize - this will fail because Bob closes immediately
		handshakeErr = sAlice.Initialize(connAlice)
	}()

	// Bob immediately closes connection to simulate EOF
	time.Sleep(10 * time.Millisecond) // Let Alice send msg1
	connBob.Close()

	wg.Wait()

	// Verify we got an error
	require.Error(handshakeErr, "Expected handshake error due to EOF")

	// Verify the error is wrapped as HandshakeError
	hsErr, ok := GetHandshakeError(handshakeErr)
	require.True(ok, "Error should be a HandshakeError, got: %T - %v", handshakeErr, handshakeErr)

	// Verify the error contains useful context
	require.True(hsErr.IsInitiator, "Should be initiator")
	// The exact state depends on timing - could fail at msg1_send or msg2_receive
	require.NotEmpty(string(hsErr.State), "Should have a state")
	require.NotEmpty(hsErr.Message, "Should have a message")

	// Verify underlying error is EOF or io.ErrClosedPipe
	require.True(
		hsErr.UnderlyingError == io.EOF || hsErr.UnderlyingError == io.ErrClosedPipe,
		"Underlying error should be EOF or closed pipe, got: %v", hsErr.UnderlyingError,
	)

	// Verify basic error message contains state info
	errStr := handshakeErr.Error()
	t.Logf("Error string: %s", errStr)
	require.Contains(errStr, "message_", "Error should mention which message failed")
	require.Contains(errStr, "initiator", "Error should mention role")

	// Verify debug output contains more details
	debugStr := GetDebugError(handshakeErr)
	t.Logf("Debug output:\n%s", debugStr)
	require.Contains(debugStr, "HANDSHAKE FAILURE", "Debug should have header")
	require.Contains(debugStr, "State:", "Debug should mention state")
	require.Contains(debugStr, "PROTOCOL INFORMATION", "Debug should have protocol info")
	require.Contains(debugStr, "KEM Scheme:", "Debug should show KEM scheme")
}

// TestHandshakeErrorWrapping_ProtocolVersion tests that protocol version
// mismatches are properly reported.
func TestHandshakeErrorWrapping_ProtocolVersion(t *testing.T) {
	require := require.New(t)

	scheme := testingScheme
	authKEMKeyAlicePub, authKEMKeyAlice, err := scheme.GenerateKeyPair()
	require.NoError(err)

	credsAlice := &PeerCredentials{
		AdditionalData: []byte("alice@example.com"),
		PublicKey:      authKEMKeyAlicePub,
	}

	authKEMKeyBobPub, _, err := scheme.GenerateKeyPair()
	require.NoError(err)

	credsBob := &PeerCredentials{
		AdditionalData: []byte("bob@example.com"),
		PublicKey:      authKEMKeyBobPub,
	}

	nike := ecdh.Scheme(rand.Reader)
	geometry := geo.GeometryFromUserForwardPayloadLength(nike, 3000, true, 5)

	// Bob's session setup (responder)
	cfgBob := &SessionConfig{
		KEMScheme:         testingScheme,
		Geometry:          geometry,
		Authenticator:     &stubAuthenticator{creds: credsAlice},
		AdditionalData:    credsBob.AdditionalData,
		AuthenticationKey: authKEMKeyAlice, // Use Alice's key for Bob
		RandomReader:      rand.Reader,
	}
	sBob, err := NewSession(cfgBob, false)
	require.NoError(err, "Bob NewSession()")

	connAlice, connBob := net.Pipe()

	var wg sync.WaitGroup
	var handshakeErr error

	wg.Add(1)
	go func() {
		defer wg.Done()
		defer connBob.Close()
		handshakeErr = sBob.Initialize(connBob)
	}()

	// Send invalid protocol version (wrong first byte)
	go func() {
		defer connAlice.Close()
		// Send wrong protocol version byte followed by garbage
		wrongProlog := []byte{0x99} // Wrong version
		connAlice.Write(wrongProlog)
		// Write enough garbage to fill msg1
		garbage := make([]byte, 2000)
		connAlice.Write(garbage)
	}()

	wg.Wait()

	require.Error(handshakeErr, "Expected protocol version error")

	// Check if it's a ProtocolVersionError
	if pvErr, ok := handshakeErr.(*ProtocolVersionError); ok {
		t.Logf("Protocol version error: %s", pvErr.Error())
		t.Logf("Debug: %s", pvErr.Debug())
		require.Equal([]byte{0x99}, pvErr.Received, "Should have received wrong version")
	} else {
		// It might be wrapped differently, check the error message
		errStr := handshakeErr.Error()
		t.Logf("Error: %s", errStr)
		require.True(
			strings.Contains(errStr, "version") || strings.Contains(errStr, "protocol"),
			"Error should mention protocol/version issue",
		)
	}
}

// rejectingAuthenticator always rejects peers
type rejectingAuthenticator struct{}

func (r *rejectingAuthenticator) IsPeerValid(peer *PeerCredentials) bool {
	return false
}

// TestHandshakeErrorWrapping_AuthFailure tests that authentication failures
// are properly reported with AuthenticationError.
func TestHandshakeErrorWrapping_AuthFailure(t *testing.T) {
	require := require.New(t)

	scheme := testingScheme
	authKEMKeyAlicePub, authKEMKeyAlice, err := scheme.GenerateKeyPair()
	require.NoError(err)

	credsAlice := &PeerCredentials{
		AdditionalData: []byte("alice@example.com"),
		PublicKey:      authKEMKeyAlicePub,
	}

	authKEMKeyBobPub, authKEMKeyBob, err := scheme.GenerateKeyPair()
	require.NoError(err)

	credsBob := &PeerCredentials{
		AdditionalData: []byte("bob@example.com"),
		PublicKey:      authKEMKeyBobPub,
	}

	nike := ecdh.Scheme(rand.Reader)
	geometry := geo.GeometryFromUserForwardPayloadLength(nike, 3000, true, 5)

	// Alice's session setup (initiator) - uses rejectingAuthenticator
	cfgAlice := &SessionConfig{
		KEMScheme:         testingScheme,
		Geometry:          geometry,
		Authenticator:     &rejectingAuthenticator{}, // Will reject Bob
		AdditionalData:    credsAlice.AdditionalData,
		AuthenticationKey: authKEMKeyAlice,
		RandomReader:      rand.Reader,
	}
	sAlice, err := NewSession(cfgAlice, true)
	require.NoError(err, "Alice NewSession()")

	// Bob's session setup (responder) - normal authenticator
	cfgBob := &SessionConfig{
		KEMScheme:         testingScheme,
		Geometry:          geometry,
		Authenticator:     &stubAuthenticator{creds: credsAlice},
		AdditionalData:    credsBob.AdditionalData,
		AuthenticationKey: authKEMKeyBob,
		RandomReader:      rand.Reader,
	}
	sBob, err := NewSession(cfgBob, false)
	require.NoError(err, "Bob NewSession()")

	connAlice, connBob := net.Pipe()

	var wg sync.WaitGroup
	var aliceErr error

	wg.Add(1)
	go func() {
		defer wg.Done()
		defer connAlice.Close()
		aliceErr = sAlice.Initialize(connAlice)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		defer connBob.Close()
		// Bob's handshake - we don't care about the result
		_ = sBob.Initialize(connBob)
	}()

	wg.Wait()

	// Alice should get an authentication error because she rejects Bob
	require.Error(aliceErr, "Expected authentication error")

	errStr := aliceErr.Error()
	t.Logf("Error string: %s", errStr)
	require.Contains(errStr, "authentication", "Error should mention authentication")

	debugStr := GetDebugError(aliceErr)
	t.Logf("Debug output:\n%s", debugStr)
	require.Contains(debugStr, "AUTHENTICATION", "Debug should have authentication header")
}

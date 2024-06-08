// session_test.go - Tests for common code of the noise based wire protocol.
// Copyright (C) 2017  David Anthony Stainton, Yawning Angel
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package wire

import (
	"crypto/rand"
	"crypto/subtle"
	"net"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	ecdh "github.com/katzenpost/hpqc/nike/x25519"

	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/katzenpost/katzenpost/core/wire/commands"
)

type stubAuthenticator struct {
	creds *PeerCredentials
}

func (s *stubAuthenticator) IsPeerValid(peer *PeerCredentials) bool {
	if subtle.ConstantTimeCompare(s.creds.AdditionalData, peer.AdditionalData) != 1 {
		return false
	}
	blob1, err := s.creds.PublicKey.MarshalBinary()
	if err != nil {
		panic(err)
	}
	blob2, err := peer.PublicKey.MarshalBinary()
	if err != nil {
		panic(err)
	}
	if subtle.ConstantTimeCompare(blob1, blob2) != 1 {
		return false
	}

	return true
}

func TestSessionIntegration(t *testing.T) {
	t.Parallel()
	assert := assert.New(t)
	require := require.New(t)

	// Helper for packet comparison.
	requireSendPktEq := func(cmd commands.Command, expected []byte) {
		var tCmp commands.SendPacket
		require.IsType(&tCmp, cmd)
		sndCmd := cmd.(*commands.SendPacket)
		require.Equal(expected, sndCmd.SphinxPacket)
	}

	// Generate the credentials used for authentication.  In a real deployment,
	// this information is conveyed out of band somehow to the peer a priori.
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
		AdditionalData: []byte("katzenpost.example.com"),
		PublicKey:      authKEMKeyBobPub,
	}

	nike := ecdh.Scheme(rand.Reader)
	userForwardPayloadLength := 3000
	withSURB := true
	nrHops := 5
	geometry := geo.GeometryFromUserForwardPayloadLength(nike,
		userForwardPayloadLength,
		withSURB,
		nrHops,
	)

	// Alice's session setup.
	cfgAlice := &SessionConfig{
		KEMScheme:         testingScheme,
		Geometry:          geometry,
		Authenticator:     &stubAuthenticator{creds: credsBob},
		AdditionalData:    credsAlice.AdditionalData,
		AuthenticationKey: authKEMKeyAlice,
		RandomReader:      rand.Reader,
	}
	// was previously sAlice, err := NewSession(cfgAlice, true)
	sAlice, err := NewSession(cfgAlice, false)
	require.NoError(err, "Integration: Alice NewSession()")

	// Bob's session setup.
	cfgBob := &SessionConfig{
		KEMScheme:         testingScheme,
		Geometry:          geometry,
		Authenticator:     &stubAuthenticator{creds: credsAlice},
		AdditionalData:    credsBob.AdditionalData,
		AuthenticationKey: authKEMKeyBob,
		RandomReader:      rand.Reader,
	}
	// was previously sBob, err := NewSession(cfgBob, false)
	sBob, err := NewSession(cfgBob, true)
	require.NoError(err, "Integration: Bob NewSession()")

	t.Log("before Pipe")
	// Try handshaking and sending a simple command.
	connAlice, connBob := net.Pipe()
	var wg sync.WaitGroup
	wg.Add(1)

	const (
		testPayload1 = "\"And 'Will to equality' -that itself shall henceforth be the name of virtue; and against everything that has power we will raise our outcry!\""
		testPayload2 = "You preachers of equality, the tyrant-madness of impotence cries this in you for \"equality\": thus your most secret tyrant appetite disguies itself in words of virtue!"
	)

	go func(s *Session, conn net.Conn) {
		// Alice's side.
		defer conn.Close()
		defer s.Close()
		defer wg.Done()

		t.Log("before Alice Initialize")
		err := s.Initialize(conn)
		require.NoError(err, "Integration: Alice Initialize()")

		t.Logf("ClockSkew: %v", s.ClockSkew())
		creds, err := s.PeerCredentials()
		require.NoError(err)
		require.Equal(credsBob.AdditionalData, creds.AdditionalData, "Integration: Alice PeerCredentials")
		assert.True(credsBob.PublicKey.Equal(creds.PublicKey), "Integration: Alice PeerCredentials")

		cmd := &commands.SendPacket{
			SphinxPacket: []byte(testPayload1),
			Cmds:         s.GetCommands(),
		}
		err = s.SendCommand(cmd)
		require.NoError(err, "Integration: Alice SendCommand() 1")

		cmd.SphinxPacket = []byte(testPayload2)
		err = s.SendCommand(cmd)
		require.NoError(err, "Integration: Alice SendCommand() 2")
	}(sAlice, connAlice)

	wg.Add(1)
	go func(s *Session, conn net.Conn) {
		// Bob's side.
		defer conn.Close()
		defer s.Close()
		defer wg.Done()

		err := s.Initialize(conn)
		require.NoError(err, "Integration: Bob Initialize()")

		assert.Panics(func() { s.ClockSkew() }, "Integration: Bob ClockSkew()")
		creds, err := s.PeerCredentials()
		require.NoError(err)
		require.Equal(credsAlice.AdditionalData, creds.AdditionalData, "Integration: Bob PeerCredentials")
		require.True(credsAlice.PublicKey.Equal(creds.PublicKey), "Integration: BobPeerCredentials")

		cmd, err := s.RecvCommand()
		require.NoError(err, "Integration: Bob RecvCommand() 1")
		requireSendPktEq(cmd, []byte(testPayload1))

		cmd, err = s.RecvCommand()
		require.NoError(err, "Integration: Bob RecvCommand() 2")
		requireSendPktEq(cmd, []byte(testPayload2))
	}(sBob, connBob)
	wg.Wait()
}

func TestAuthenticateMessageToBytes(t *testing.T) {
	t.Parallel()
	m := authenticateMessage{
		ad: make([]byte, MaxAdditionalDataLength+1),
	}
	f := func() {
		m.ToBytes(nil)
	}
	require.Panics(t, f)
}

func TestAuthenticateMessageFromBytes(t *testing.T) {
	t.Parallel()
	b := make([]byte, authLen-1)
	f := func() {
		authenticateMessageFromBytes(b)
	}
	require.Panics(t, f)
}

func TestNewSessionErrors(t *testing.T) {
	t.Parallel()
	nike := ecdh.Scheme(rand.Reader)
	userForwardPayloadLength := 3000
	withSURB := true
	nrHops := 5
	geometry := geo.GeometryFromUserForwardPayloadLength(nike,
		userForwardPayloadLength,
		withSURB,
		nrHops,
	)

	_, authKEMKeyBob, err := testingScheme.GenerateKeyPair()
	require.NoError(t, err)

	credsBob := &PeerCredentials{
		AdditionalData: []byte("katzenpost.example.com"),
		PublicKey:      authKEMKeyBob.Public(),
	}

	_, authKEMKeyWrong, err := testingScheme.GenerateKeyPair()
	require.NoError(t, err)

	// test case if cfg.Geometry == nil
	cfg := &SessionConfig{
		KEMScheme:         testingScheme,
		Geometry:          geometry,
		Authenticator:     &stubAuthenticator{creds: credsBob},
		AdditionalData:    make([]byte, MaxAdditionalDataLength),
		AuthenticationKey: authKEMKeyWrong,
		RandomReader:      rand.Reader,
	}
	_, err = NewSession(cfg, false)
	require.NoError(t, err)
	cfg.Geometry = nil
	_, err = NewSession(cfg, false)
	require.Error(t, err)

	// test case if cfg.Authenticator == nil
	cfg = &SessionConfig{
		KEMScheme:         testingScheme,
		Geometry:          geometry,
		AdditionalData:    make([]byte, MaxAdditionalDataLength),
		AuthenticationKey: authKEMKeyWrong,
		RandomReader:      rand.Reader,
	}
	_, err = NewSession(cfg, false)
	require.Error(t, err)

	// test case if len(cfg.AdditionalData) > MaxAdditionalDataLength
	cfg = &SessionConfig{
		KEMScheme:         testingScheme,
		Geometry:          geometry,
		AdditionalData:    make([]byte, MaxAdditionalDataLength+1),
		AuthenticationKey: authKEMKeyWrong,
		RandomReader:      rand.Reader,
	}
	_, err = NewSession(cfg, false)
	require.Error(t, err)

	// test case if cfg.AuthenticationKey == nil
	cfg = &SessionConfig{
		KEMScheme:      testingScheme,
		Geometry:       geometry,
		Authenticator:  &stubAuthenticator{creds: credsBob},
		AdditionalData: make([]byte, MaxAdditionalDataLength),
		RandomReader:   rand.Reader,
	}
	_, err = NewSession(cfg, false)
	require.Error(t, err)

	// test case if cfg.RandomReader == nil {
	cfg = &SessionConfig{
		KEMScheme:         testingScheme,
		Geometry:          geometry,
		Authenticator:     &stubAuthenticator{creds: credsBob},
		AdditionalData:    make([]byte, MaxAdditionalDataLength),
		AuthenticationKey: authKEMKeyWrong,
	}
	_, err = NewSession(cfg, false)
	require.Error(t, err)
}

func TestErrorInvalidStatePeerCreds(t *testing.T) {
	t.Parallel()
	nike := ecdh.Scheme(rand.Reader)
	userForwardPayloadLength := 3000
	withSURB := true
	nrHops := 5
	geometry := geo.GeometryFromUserForwardPayloadLength(nike,
		userForwardPayloadLength,
		withSURB,
		nrHops,
	)

	_, authKEMKeyBob, err := testingScheme.GenerateKeyPair()
	require.NoError(t, err)

	credsBob := &PeerCredentials{
		AdditionalData: []byte("katzenpost.example.com"),
		PublicKey:      authKEMKeyBob.Public(),
	}

	_, authKEMKeyWrong, err := testingScheme.GenerateKeyPair()
	require.NoError(t, err)

	// test case if cfg.Geometry == nil
	cfg := &SessionConfig{
		KEMScheme:         testingScheme,
		Geometry:          geometry,
		Authenticator:     &stubAuthenticator{creds: credsBob},
		AdditionalData:    make([]byte, MaxAdditionalDataLength),
		AuthenticationKey: authKEMKeyWrong,
		RandomReader:      rand.Reader,
	}
	s, err := NewSession(cfg, false)
	require.NoError(t, err)

	_, err = s.PeerCredentials()
	require.Error(t, err)
}

func TestErrorInvalidStateClockSkew(t *testing.T) {
	t.Parallel()
	nike := ecdh.Scheme(rand.Reader)
	userForwardPayloadLength := 3000
	withSURB := true
	nrHops := 5
	geometry := geo.GeometryFromUserForwardPayloadLength(nike,
		userForwardPayloadLength,
		withSURB,
		nrHops,
	)

	_, authKEMKeyBob, err := testingScheme.GenerateKeyPair()
	require.NoError(t, err)

	credsBob := &PeerCredentials{
		AdditionalData: []byte("katzenpost.example.com"),
		PublicKey:      authKEMKeyBob.Public(),
	}

	_, authKEMKeyWrong, err := testingScheme.GenerateKeyPair()
	require.NoError(t, err)

	// test case if cfg.Geometry == nil
	cfg := &SessionConfig{
		KEMScheme:         testingScheme,
		Geometry:          geometry,
		Authenticator:     &stubAuthenticator{creds: credsBob},
		AdditionalData:    make([]byte, MaxAdditionalDataLength),
		AuthenticationKey: authKEMKeyWrong,
		RandomReader:      rand.Reader,
	}
	s, err := NewSession(cfg, false)
	require.NoError(t, err)
	f := func() {
		_ = s.ClockSkew()
	}
	require.Panics(t, f)
}

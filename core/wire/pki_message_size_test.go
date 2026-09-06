// SPDX-FileCopyrightText: © 2026 Jacob Appelbaum
// SPDX-License-Identifier: AGPL-3.0-only

package wire

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/rand"

	"github.com/katzenpost/katzenpost/core/wire/commands"
)

func newPKIConfig(t *testing.T, maxSize int) *SessionConfig {
	t.Helper()
	pub, priv, err := testingScheme.GenerateKeyPair()
	require.NoError(t, err)
	return &SessionConfig{
		KEMScheme:         testingScheme,
		Authenticator:     &stubAuthenticator{creds: &PeerCredentials{AdditionalData: []byte("peer"), PublicKey: pub}},
		AdditionalData:    []byte("me"),
		AuthenticationKey: priv,
		RandomReader:      rand.Reader,
		MaxMessageSize:    maxSize,
	}
}

// TestPKISessionDefaultMaxMessageSize pins the sane default: a PKI session with
// no configured ceiling uses DefaultMaxPKIMessageSize, which is far below the
// 500 MB backstop.
func TestPKISessionDefaultMaxMessageSize(t *testing.T) {
	s, err := NewPKISession(newPKIConfig(t, 0), true)
	require.NoError(t, err)
	require.Equal(t, DefaultMaxPKIMessageSize, s.MaxMesgSize())
	require.Less(t, s.MaxMesgSize(), MaxMessageSize)
}

// TestPKISessionConfiguredMaxMessageSize verifies the ceiling is configurable.
func TestPKISessionConfiguredMaxMessageSize(t *testing.T) {
	s, err := NewPKISession(newPKIConfig(t, 4242), true)
	require.NoError(t, err)
	require.Equal(t, 4242, s.MaxMesgSize())
}

// TestSessionRejectsOversizedCommandOnReceive proves the ceiling is enforced on
// receive: a command whose length exceeds the receiver's ceiling is rejected
// after the header, before the body is read.
func TestSessionRejectsOversizedCommandOnReceive(t *testing.T) {
	alice, bob := deadlineTestConfigs(t)
	sA, sB, cA, cB := establishTestPair(t, alice, bob)
	defer sA.Close()
	defer sB.Close()
	defer cA.Close()
	defer cB.Close()

	// Shrink the receiver's ceiling below any real command.
	sB.maxMesgSize = 10

	go func() { _ = sA.SendCommand(context.Background(), &commands.NoOp{Cmds: sA.commands}) }()

	_, err := sB.RecvCommand(context.Background())
	require.Equal(t, errMsgSize, err)
}

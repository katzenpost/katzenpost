// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/nike/schemes"
	"github.com/katzenpost/hpqc/rand"

	"github.com/katzenpost/katzenpost/core/log"
	cpki "github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/wire"
	"github.com/katzenpost/katzenpost/core/wire/commands"
)

func logLevels(text string) []string {
	var levels []string
	for _, line := range strings.Split(strings.TrimSpace(text), "\n") {
		if fields := strings.Fields(line); len(fields) > 1 {
			levels = append(levels, fields[1])
		}
	}
	return levels
}

func receiveAndLog(t *testing.T, courier *Courier, cmd func(*commands.Commands) commands.Command) string {
	t.Helper()
	_, linkKey, err := benchKEMScheme.GenerateKeyPair()
	require.NoError(t, err)
	newSession := func(initiator bool) *wire.Session {
		s, err := wire.NewStorageReplicaSession(&wire.SessionConfig{
			KEMScheme:         benchKEMScheme,
			Geometry:          benchGeometry,
			Authenticator:     &acceptAllAuthenticator{},
			AuthenticationKey: linkKey,
			RandomReader:      rand.Reader,
		}, schemes.ByName("x25519"), initiator)
		require.NoError(t, err)
		return s
	}
	local, remote := newSession(true), newSession(false)
	localConn, remoteConn := net.Pipe()
	errCh := make(chan error, 1)
	go func() {
		if err := remote.Initialize(context.Background(), remoteConn); err != nil {
			errCh <- err
			return
		}
		errCh <- remote.SendCommand(context.Background(), cmd(remote.GetCommands()))
	}()
	require.NoError(t, local.Initialize(context.Background(), localConn))

	path := filepath.Join(t.TempDir(), "courier.log")
	backend, err := log.New(path, "DEBUG", false)
	require.NoError(t, err)
	c := &outgoingConn{
		courier: courier,
		log:     backend.GetLogger("conn"),
		dst:     &cpki.ReplicaDescriptor{Name: "storagereplica9"},
	}
	done := make(chan struct{})
	require.True(t, c.handleCommand(c.processIncomingReply(<-c.startPeerReader(local, done))))
	require.NoError(t, <-errCh)
	localConn.Close()
	remoteConn.Close()
	close(done)
	c.Halt()
	local.Close()
	remote.Close()

	b, err := os.ReadFile(path)
	require.NoError(t, err)
	return string(b)
}

func TestReceiveLogsDecoyLikeReal(t *testing.T) {
	courier := createTestCourier(t)
	decoy := receiveAndLog(t, courier, func(cmds *commands.Commands) commands.Command {
		return &commands.ReplicaDecoy{Cmds: cmds}
	})
	real := receiveAndLog(t, courier, func(cmds *commands.Commands) commands.Command {
		return &commands.ReplicaMessageReply{Cmds: cmds, EnvelopeHash: &[32]byte{1}}
	})
	require.Equal(t, logLevels(real), logLevels(decoy), "decoy and real replies log differently")
}

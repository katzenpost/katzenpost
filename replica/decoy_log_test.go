// SPDX-License-Identifier: AGPL-3.0-only

package replica

import (
	"context"
	"io"
	"net"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/nike/schemes"
	"github.com/katzenpost/hpqc/rand"

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

func storageSession(t *testing.T) *wire.Session {
	t.Helper()
	_, linkKey, err := benchKEMScheme.GenerateKeyPair()
	require.NoError(t, err)
	newSession := func(initiator bool) *wire.Session {
		s, err := wire.NewStorageReplicaSession(&wire.SessionConfig{
			KEMScheme:         benchKEMScheme,
			Geometry:          benchGeometry,
			Authenticator:     &benchAuthenticator{},
			AuthenticationKey: linkKey,
			RandomReader:      rand.Reader,
		}, schemes.ByName("x25519"), initiator)
		require.NoError(t, err)
		t.Cleanup(s.Close)
		return s
	}
	local, remote := newSession(false), newSession(true)
	localConn, remoteConn := net.Pipe()
	t.Cleanup(func() { localConn.Close(); remoteConn.Close() })
	errCh := make(chan error, 1)
	go func() {
		errCh <- remote.Initialize(context.Background(), remoteConn)
		_, _ = io.Copy(io.Discard, remoteConn)
	}()
	require.NoError(t, local.Initialize(context.Background(), localConn))
	require.NoError(t, <-errCh)
	return local
}

func TestSendResponseLogsDecoyLikeReal(t *testing.T) {
	session := storageSession(t)
	cmds := session.GetCommands()
	send := func(module string, req *senderRequest) string {
		logger, path := replicaPayloadLogger(t, module)
		(&incomingConn{log: logger}).sendResponse(session, req)
		return replicaPayloadLogText(t, path)
	}
	decoy := send("decoy", &senderRequest{ReplicaDecoy: &commands.ReplicaDecoy{Cmds: cmds}})
	real := send("real", &senderRequest{ReplicaWriteReply: &commands.ReplicaWriteReply{Cmds: cmds}})
	require.Equal(t, logLevels(real), logLevels(decoy), "decoy and real responses log differently")
}

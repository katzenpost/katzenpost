// SPDX-License-Identifier: AGPL-3.0-only

package client

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/core/wire"
	"github.com/katzenpost/katzenpost/core/wire/commands"
)

func TestAbandonedGetConsensusDoesNotWedgeTheLink(t *testing.T) {
	env := newTestGatewayEnv(t)
	clientCfg := setupTestGatewayFull(t, "tcp://127.0.0.1:0", env, func(t *testing.T, wireConn *wire.Session, cmds *commands.Commands, cmd commands.Command) bool {
		return true
	})
	setupClientCallbacks(clientCfg)
	logbackend, err := log.New("", "DEBUG", false)
	require.NoError(t, err)
	c, err := New(clientCfg, logbackend)
	require.NoError(t, err)
	c.conn = newConnection(c)
	c.maxConsensusSize = 1 << 20
	c.pki = newPKI(c)
	c.conn.start()
	defer c.Shutdown()
	require.Eventually(t, c.conn.isConnected.Load, 30*time.Second, 10*time.Millisecond)

	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	_, err = c.conn.GetConsensus(ctx, 1)
	cancel()
	require.ErrorIs(t, err, errGetConsensusCanceled)

	ctx, cancel = context.WithTimeout(context.Background(), 2*time.Second)
	_, err = c.conn.GetConsensus(ctx, 2)
	cancel()
	require.Error(t, err)
	require.NotContains(t, err.Error(), "outstanding GetConsensus")
	require.Eventually(t, func() bool { return !c.conn.isConnected.Load() }, 5*time.Second, 10*time.Millisecond)
}

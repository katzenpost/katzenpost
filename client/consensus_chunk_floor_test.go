// SPDX-License-Identifier: AGPL-3.0-only

package client

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/nike/schemes"

	"github.com/katzenpost/katzenpost/core/cert"
	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/log"
	cpki "github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/wire"
	"github.com/katzenpost/katzenpost/core/wire/commands"
)

func TestConsensusChunksBelowOurChunkSizeCloseTheLink(t *testing.T) {
	env := newTestGatewayEnv(t)
	const chunkSize = 64
	sent := make(chan int, 1)
	clientCfg := setupTestGatewayFull(t, "tcp://127.0.0.1:12381", env, func(t *testing.T, wireConn *wire.Session, cmds *commands.Commands, cmd commands.Command) bool {
		req, ok := cmd.(*commands.GetConsensus2)
		if !ok {
			return true
		}
		doc := generateDocument(t, env.pkiScheme, env.linkScheme, schemes.ByName("x25519"), env.nikeScheme, nil, 3, 3, 0, env.geo, req.Epoch)
		docBytes, err := ccbor.Marshal((*document)(doc))
		if err != nil {
			return false
		}
		raw, err := cert.Sign(env.authKeys[0].priv, env.authKeys[0].pub, docBytes, req.Epoch+5)
		if err != nil {
			return false
		}
		for _, k := range env.authKeys[1:] {
			if raw, err = cert.SignMulti(k.priv, k.pub, raw); err != nil {
				return false
			}
		}
		chunks, err := cpki.Chunk(raw, chunkSize)
		if err != nil {
			return false
		}
		sent <- len(chunks)
		for i, chunk := range chunks {
			if wireConn.SendCommand(context.Background(), &commands.Consensus2{
				Cmds:       cmds,
				ErrorCode:  commands.ConsensusOk,
				ChunkNum:   uint32(i),
				ChunkTotal: uint32(len(chunks)),
				Payload:    chunk,
			}) != nil {
				return false
			}
		}
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

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	epoch, _, _ := epochtime.Now()
	_, err = c.conn.GetConsensus(ctx, epoch)
	select {
	case n := <-sent:
		require.Greater(t, n, 1)
	case <-time.After(time.Second):
		require.FailNow(t, "the gateway never sent the document")
	}
	require.Error(t, err)
}

// SPDX-License-Identifier: AGPL-3.0-only

package replica

import (
	"bytes"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/kem/mkem"
	"github.com/katzenpost/hpqc/nike"
	"github.com/katzenpost/hpqc/rand"
	"github.com/katzenpost/hpqc/sign"
	"github.com/katzenpost/hpqc/sign/ed25519"

	"github.com/katzenpost/katzenpost/core/wire/commands"
	"github.com/katzenpost/katzenpost/pigeonhole"
	replicaCommon "github.com/katzenpost/katzenpost/replica/common"
)

// gatingConnector counts DispatchReplication calls and parks each one on
// a gate, so a successful local write holds its handler goroutine (and
// its decap slot) until the test releases the gate.
type gatingConnector struct {
	*mockConnector
	entered atomic.Int64
	gate    chan struct{}
}

func (c *gatingConnector) DispatchReplication(cmd *commands.ReplicaWrite) {
	c.entered.Add(1)
	<-c.gate
}

// localWriteReplicaMessage builds a genuine ReplicaMessage carrying a
// BACAP write for a box this server shards, MKEM-encapsulated to the
// server's current-epoch envelope key. handleReplicaMessage decapsulates
// it, writes it locally and then calls connector.DispatchReplication.
func localWriteReplicaMessage(t *testing.T, env *semaScopeTestEnv) *commands.ReplicaMessage {
	t.Helper()
	edScheme := ed25519.Scheme()
	myIDKey, err := env.server.identityPublicKey.MarshalBinary()
	require.NoError(t, err)

	payloadLen := env.pigeonGeo.CalculateBoxCiphertextLength()

	var boxID [32]byte
	var priv sign.PrivateKey
	found := false
	for i := 0; i < 500; i++ {
		pub, sk, err := edScheme.GenerateKey()
		require.NoError(t, err)
		pubBytes, err := pub.MarshalBinary()
		require.NoError(t, err)
		copy(boxID[:], pubBytes)
		shards, err := replicaCommon.GetShards(&boxID, env.doc)
		require.NoError(t, err)
		for _, shard := range shards {
			if bytes.Equal(shard.IdentityKey, myIDKey) {
				found = true
				break
			}
		}
		if found {
			priv = sk
			break
		}
	}
	require.True(t, found, "could not find a box this server shards")

	payload := make([]byte, payloadLen)
	_, err = rand.Reader.Read(payload)
	require.NoError(t, err)
	sig := edScheme.Sign(priv, payload, nil)
	var sigArr [64]byte
	copy(sigArr[:], sig)

	inner := &pigeonhole.ReplicaInnerMessage{
		MessageType: 1,
		WriteMsg: &pigeonhole.ReplicaWrite{
			BoxID:      boxID,
			Signature:  sigArr,
			PayloadLen: uint32(len(payload)),
			Payload:    payload,
		},
	}
	padded, err := pigeonhole.PadInnerMessageForEncryption(inner, env.server.pigeonholeGeo)
	require.NoError(t, err)
	replicaEpoch, _, _ := replicaCommon.ReplicaNow()
	keypair, err := env.server.envelopeKeys.GetKeypair(replicaEpoch)
	require.NoError(t, err)
	_, ct, err := replicaCommon.MKEMNikeScheme.Encapsulate([]nike.PublicKey{keypair.PublicKey}, padded)
	require.NoError(t, err)
	return &commands.ReplicaMessage{
		Cmds:               commands.NewStorageReplicaCommands(env.server.cfg.SphinxGeometry, replicaCommon.NikeScheme),
		PigeonholeGeometry: env.server.pigeonholeGeo,
		Scheme:             replicaCommon.NikeScheme,
		SenderEPubKey:      ct.EphemeralPublicKey.Bytes(),
		DEK:                (*[mkem.DEKSize]byte)(ct.DEKCiphertexts[0]),
		Ciphertext:         ct.Envelope,
	}
}

// TestReplicaMessageDecapConcurrencyBounded proves that a burst of
// pipelined ReplicaMessages cannot spawn more concurrent local
// decapsulations than the worker pool permits. Each message decapsulates
// (a CTIDH group action) and then parks in DispatchReplication while
// still holding its decap slot, so the number that reach the connector is
// exactly the pool size; the command loop back-pressures on the rest.
// Pre-fix, every ReplicaMessage got its own goroutine and all of them ran
// concurrently.
func TestReplicaMessageDecapConcurrencyBounded(t *testing.T) {
	var fireWg sync.WaitGroup
	var server *Server
	// Registered before setup so it runs AFTER setup's listener.Halt()
	// (t.Cleanup is LIFO). Halt closes closeAllCh and the gate cleanup
	// (registered later, so it runs first) unblocks the parked handlers;
	// this join then waits for them to unwind.
	t.Cleanup(func() {
		fireWg.Wait()
		if server != nil {
			server.handlerWg.Wait()
		}
	})

	env := setupSemaScopeTestServer(t)
	server = env.server

	// The decap pool is ProxyWorkerCount (1 in this harness). Widen the
	// proxy pool so it is not the bound under observation.
	bound := int64(env.cfg.ProxyWorkerCount)
	env.server.proxySema = make(chan struct{}, 1024)

	cc := &gatingConnector{
		mockConnector: newMockConnector(env.server),
		gate:          make(chan struct{}),
	}
	env.server.connector = cc
	t.Cleanup(func() { close(cc.gate) })

	const burst = 4
	msgs := make([]*commands.ReplicaMessage, burst)
	for i := range msgs {
		msgs[i] = localWriteReplicaMessage(t, env)
	}

	fireWg.Add(1)
	go func() {
		defer fireWg.Done()
		for _, msg := range msgs {
			env.inConn.onReplicaCommand(msg, env.emitter)
		}
	}()

	require.Eventually(t, func() bool { return cc.entered.Load() == bound }, semaScopeReplyBudget, 20*time.Millisecond,
		"the first %d decapsulation(s) never reached the connector", bound)
	require.Never(t, func() bool { return cc.entered.Load() > bound }, 10*time.Second, 50*time.Millisecond,
		"more than %d ReplicaMessage decapsulations ran concurrently", bound)
	require.Equal(t, bound, cc.entered.Load())
}

// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package replica

import (
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/blake2b"

	"github.com/katzenpost/hpqc/kem/mkem"
	"github.com/katzenpost/hpqc/rand"

	"github.com/katzenpost/katzenpost/core/wire/commands"
	"github.com/katzenpost/katzenpost/pigeonhole"
	replicaCommon "github.com/katzenpost/katzenpost/replica/common"
)

// holderScript says how one shard holder behaves when a proxied read
// reaches it. A silent holder never answers, which is what a congested
// link or a downed peer looks like from the proxying replica.
type holderScript struct {
	silent    bool
	bare      bool
	errorCode uint8
}

// scriptedConnector answers proxied reads on behalf of shard holders
// and records every command dispatched, so a test can assert whether a
// read-repair write was sent and to whom.
//
// Responses are scripted in dispatch order rather than per peer,
// because proxyReadRequest picks its first candidate at random
// (CryptoRandIndex). A test that pinned behaviour to a named holder
// would pass or fail on the coin flip; scripting the sweep positions
// describes the scenario the test actually means.
//
// It embeds mockConnector for the GenericConnector methods it does not
// care about, and overrides DispatchCommand alone.
type scriptedConnector struct {
	*mockConnector

	sync.Mutex
	responses  []holderScript
	next       int
	answered   [][32]byte
	keys       map[[32]byte]*TestKeys
	dispatched []dispatchedCommand
	env        *semaScopeTestEnv
	t          *testing.T
}

type dispatchedCommand struct {
	cmd    commands.Command
	idHash [32]byte
}

func newScriptedConnector(t *testing.T, env *semaScopeTestEnv, responses ...holderScript) *scriptedConnector {
	t.Helper()

	sc := &scriptedConnector{
		mockConnector: newMockConnector(env.server),
		responses:     responses,
		keys:          make(map[[32]byte]*TestKeys, len(env.holders)),
		env:           env,
		t:             t,
	}
	for i, holder := range env.holders {
		sc.keys[blake2b.Sum256(holder.IdentityKey)] = env.holderKeys[i]
	}
	return sc
}

func (sc *scriptedConnector) DispatchCommand(cmd commands.Command, idHash *[32]byte) {
	sc.Lock()
	sc.dispatched = append(sc.dispatched, dispatchedCommand{cmd: cmd, idHash: *idHash})
	keys := sc.keys[*idHash]

	msg, isProxyRequest := cmd.(*commands.ReplicaMessage)
	if !isProxyRequest || keys == nil || sc.next >= len(sc.responses) {
		// Repair writes, unknown peers and requests past the end of
		// the script are recorded but never answered.
		sc.Unlock()
		return
	}
	script := sc.responses[sc.next]
	sc.next++
	sc.answered = append(sc.answered, *idHash)
	sc.Unlock()

	if script.silent {
		return
	}
	if script.bare {
		// A holder that failed before it could encrypt anything, so its
		// reply carries an error code and no envelope.
		sc.env.server.proxyManager.HandleReply(&commands.ReplicaMessageReply{
			ErrorCode:    script.errorCode,
			EnvelopeHash: msg.EnvelopeHash(),
		})
		return
	}
	sc.answerAsHolder(msg, keys, script)
}

// peerAtSweepPosition returns the holder that received the nth proxied
// request, so a test can name the peer its script addressed without
// assuming which holder the random first pick chose.
func (sc *scriptedConnector) peerAtSweepPosition(n int) [32]byte {
	sc.Lock()
	defer sc.Unlock()
	require.Greater(sc.t, len(sc.answered), n, "sweep did not reach position %d", n)
	return sc.answered[n]
}

// answerAsHolder decapsulates the proxied request with the holder's
// envelope key, then hands the proxy manager a reply encrypted back to
// the proxying replica's ephemeral key, exactly as a real holder would.
func (sc *scriptedConnector) answerAsHolder(msg *commands.ReplicaMessage, keys *TestKeys, script holderScript) {
	t := sc.t
	nikeScheme := replicaCommon.NikeScheme
	scheme := mkem.NewScheme(nikeScheme)

	senderEPub, err := nikeScheme.UnmarshalBinaryPublicKey(msg.SenderEPubKey)
	require.NoError(t, err)

	plaintext, err := scheme.Decapsulate(keys.ReplicaPrivKey, &mkem.Ciphertext{
		EphemeralPublicKey: senderEPub,
		DEKCiphertexts:     [][]byte{msg.DEK[:]},
		Envelope:           msg.Ciphertext,
	})
	require.NoError(t, err)
	innerBytes, err := pigeonhole.ExtractMessageFromPaddedPayload(plaintext)
	require.NoError(t, err)
	request, err := pigeonhole.ParseReplicaInnerMessage(innerBytes)
	require.NoError(t, err)
	require.NotNil(t, request.ReadMsg, "scripted connector only answers reads")

	readReply := &pigeonhole.ReplicaReadReply{
		BoxID:     request.ReadMsg.BoxID,
		ErrorCode: script.errorCode,
	}
	if script.errorCode == pigeonhole.ReplicaSuccess {
		payload := make([]byte, sc.env.pigeonGeo.CalculateBoxCiphertextLength())
		_, err = rand.Reader.Read(payload)
		require.NoError(t, err)
		readReply.Payload = payload
		readReply.PayloadLen = uint32(len(payload))
	}

	blob, err := pigeonhole.PadReplyInnerMessageForEncryption(
		&pigeonhole.ReplicaMessageReplyInnerMessage{ReadReply: readReply}, sc.env.pigeonGeo)
	require.NoError(t, err)
	envelope := scheme.EnvelopeReply(keys.ReplicaPrivKey, senderEPub, blob)

	sc.env.server.proxyManager.HandleReply(&commands.ReplicaMessageReply{
		Cmds:               commands.NewStorageReplicaCommands(sc.env.sphinxGeo, nikeScheme),
		PigeonholeGeometry: sc.env.pigeonGeo,
		ErrorCode:          script.errorCode,
		EnvelopeHash:       msg.EnvelopeHash(),
		EnvelopeReply:      envelope.Envelope,
	})
}

// repairWrites returns the read-repair writes dispatched so far,
// keyed by the peer they were addressed to.
func (sc *scriptedConnector) repairWrites() map[[32]byte]*commands.ReplicaWrite {
	sc.Lock()
	defer sc.Unlock()
	writes := make(map[[32]byte]*commands.ReplicaWrite)
	for _, d := range sc.dispatched {
		if w, ok := d.cmd.(*commands.ReplicaWrite); ok {
			writes[d.idHash] = w
		}
	}
	return writes
}

// proxyReadThroughSweep drives a real proxied read for a box this
// server does not shard, and returns the reply the client would see.
func proxyReadThroughSweep(t *testing.T, env *semaScopeTestEnv) *commands.ReplicaMessageReply {
	t.Helper()
	boxID := findBoxByShardMembership(t, env.server, env.doc, false)
	msg := semaScopeValidReplicaMessage(t, env.server, boxID)

	_, ok := env.inConn.onReplicaCommand(msg, env.emitter)
	require.True(t, ok)

	select {
	case req := <-env.dummyOut:
		require.NotNil(t, req.ReplicaMessageReply)
		return req.ReplicaMessageReply
	case <-time.After(60 * time.Second):
		t.Fatal("no reply emitted for the proxied read")
		return nil
	}
}

// TestReadRepairFiresOnBoxNotFound is the positive half of the trigger
// rule. The first holder tried answers box-not-found, so the sweep must
// carry on to its co-holder rather than reporting the box missing, and
// the holder that reported it missing must be repaired.
func TestReadRepairFiresOnBoxNotFound(t *testing.T) {
	env := setupSemaScopeTestServer(t)
	sc := newScriptedConnector(t, env,
		holderScript{errorCode: pigeonhole.ReplicaErrorBoxIDNotFound},
		holderScript{errorCode: pigeonhole.ReplicaSuccess},
	)
	env.server.connector = sc

	reply := proxyReadThroughSweep(t, env)
	require.Equal(t, uint8(pigeonhole.ReplicaSuccess), reply.ErrorCode,
		"a not-found from one holder must fail over to the co-holder, not be returned")

	repairs := sc.repairWrites()
	require.Len(t, repairs, 1, "exactly the holder that reported the box missing is repaired")
	require.Contains(t, repairs, sc.peerAtSweepPosition(0),
		"the repair must go to the holder that answered box-not-found")
}

// TestNoReadRepairOnSilentHolder is the negative half. A holder that
// never answers tells us nothing about what it stores, and pushing a
// full-payload write at a peer that just failed to carry a small read
// only deepens whatever congestion caused the silence.
func TestNoReadRepairOnSilentHolder(t *testing.T) {
	env := setupSemaScopeTestServer(t)
	// The silent holder burns its share of the sweep budget before the
	// co-holder is tried. Shorten the budget so this test measures the
	// failover rather than the clock, but keep it comfortably above the
	// per-candidate MKEM encapsulation cost: that CTIDH1024 keygen and
	// group action is spent from the same budget, so too small a value
	// exhausts the sweep on crypto alone and no failover happens.
	env.server.cfg.ProxyRequestTimeout = 10
	sc := newScriptedConnector(t, env,
		holderScript{silent: true},
		holderScript{errorCode: pigeonhole.ReplicaSuccess},
	)
	env.server.connector = sc

	reply := proxyReadThroughSweep(t, env)
	require.Equal(t, uint8(pigeonhole.ReplicaSuccess), reply.ErrorCode,
		"a silent holder must fail over to the co-holder")
	require.Empty(t, sc.repairWrites(),
		"a holder that did not answer must never be read-repaired")
}

// TestBothHoldersMissingReturnsNotFound covers the exhausted sweep:
// with no good copy anywhere there is nothing to replay, so the honest
// answer goes back to the client and nobody is repaired.
func TestBothHoldersMissingReturnsNotFound(t *testing.T) {
	env := setupSemaScopeTestServer(t)
	sc := newScriptedConnector(t, env,
		holderScript{errorCode: pigeonhole.ReplicaErrorBoxIDNotFound},
		holderScript{errorCode: pigeonhole.ReplicaErrorBoxIDNotFound},
	)
	env.server.connector = sc

	reply := proxyReadThroughSweep(t, env)
	require.Equal(t, uint8(pigeonhole.ReplicaErrorBoxIDNotFound), reply.ErrorCode)
	require.Empty(t, sc.repairWrites(),
		"with no good copy there is nothing to replay, so nobody is repaired")
}

// TestTombstoneEndsSweepWithoutRepair pins the tombstone case. A
// tombstone is the true state of the box rather than a miss, so it is
// authoritative: the sweep stops and no repair is provoked.
func TestTombstoneEndsSweepWithoutRepair(t *testing.T) {
	env := setupSemaScopeTestServer(t)
	sc := newScriptedConnector(t, env,
		holderScript{errorCode: pigeonhole.ReplicaErrorTombstone},
		holderScript{errorCode: pigeonhole.ReplicaSuccess},
	)
	env.server.connector = sc

	reply := proxyReadThroughSweep(t, env)
	require.Equal(t, uint8(pigeonhole.ReplicaErrorTombstone), reply.ErrorCode,
		"a tombstone is authoritative and must not fail over")
	require.Empty(t, sc.repairWrites())
}

// TestBareReplyFailsOverAndSurfacesItsErrorCode covers the holder that
// replies with an error code but no envelope, having failed before it
// could encrypt anything. It never reached the box, so it is not a
// box-not-found answer and must not be read-repaired, and the sweep
// must carry on to the co-holder.
func TestBareReplyFailsOverAndSurfacesItsErrorCode(t *testing.T) {
	env := setupSemaScopeTestServer(t)
	sc := newScriptedConnector(t, env,
		holderScript{bare: true, errorCode: pigeonhole.ReplicaErrorInvalidEpoch},
		holderScript{errorCode: pigeonhole.ReplicaSuccess},
	)
	env.server.connector = sc

	reply := proxyReadThroughSweep(t, env)
	require.Equal(t, uint8(pigeonhole.ReplicaSuccess), reply.ErrorCode,
		"an envelope-less reply must fail over to the co-holder")
	require.Empty(t, sc.repairWrites(),
		"a holder that never reached the box must not be read-repaired")
}

// TestAllBareRepliesSurfaceTheHoldersErrorCode covers the exhausted
// version: with no holder producing a usable reply, the last error code
// a holder actually reported is more use to the client than the generic
// replication-failed code.
func TestAllBareRepliesSurfaceTheHoldersErrorCode(t *testing.T) {
	env := setupSemaScopeTestServer(t)
	sc := newScriptedConnector(t, env,
		holderScript{bare: true, errorCode: pigeonhole.ReplicaErrorInvalidEpoch},
		holderScript{bare: true, errorCode: pigeonhole.ReplicaErrorInvalidEpoch},
	)
	env.server.connector = sc

	reply := proxyReadThroughSweep(t, env)
	require.Equal(t, uint8(pigeonhole.ReplicaErrorInvalidEpoch), reply.ErrorCode,
		"the holder's own error code must reach the client, not a generic sweep failure")
	require.Empty(t, sc.repairWrites())
}

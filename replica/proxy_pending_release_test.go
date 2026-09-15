// SPDX-FileCopyrightText: Copyright (C) 2026 Katzenpost Contributors
// SPDX-License-Identifier: AGPL-3.0-only

package replica

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/wire/commands"
	"github.com/katzenpost/katzenpost/pigeonhole"
	replicaCommon "github.com/katzenpost/katzenpost/replica/common"
)

// pendingReleaseAttemptTimeout is the share of the sweep budget the
// single-attempt test hands one candidate. Nothing on that path performs
// a CTIDH1024 operation, so it only has to be long enough to be a
// deliberate wait rather than an immediate return.
const pendingReleaseAttemptTimeout = 200 * time.Millisecond

// pendingReleaseSweepBudget is the whole-sweep budget the sweep-level
// test hands a read with two holders to try. Each attempt encapsulates
// to its holder before it starts waiting, and that is a CTIDH1024
// keygen plus group action, so the budget has to cover two of those and
// still leave both attempts a wait worth timing out.
const pendingReleaseSweepBudget = 8 * time.Second

// pendingProxyRequests reports how many proxy requests the manager still
// holds registered.
func pendingProxyRequests(m *ProxyRequestManager) int {
	m.RLock()
	defer m.RUnlock()
	return len(m.pendingRequests)
}

// TestTimedOutProxyAttemptReleasesItsPendingEntry pins the rule that an
// attempt which gives up takes its registration with it.
//
// An attempt gets only its share of the sweep budget, while the periodic
// cleanup expires entries against the whole ProxyRequestTimeout. So an
// entry left behind by a timed-out attempt outlives the sweep that
// abandoned it by most of a ProxyRequestTimeout, all the while counted
// in the pending gauge an operator reads to see proxy backlog, and
// pinning the attempt's ReplicaMessage and its MKEM private key. That is
// worst exactly when it matters most: a sick holder is what makes
// attempts time out in the first place.
func TestTimedOutProxyAttemptReleasesItsPendingEntry(t *testing.T) {
	env := setupSemaScopeTestServer(t)

	// The manager expires entries against the configured
	// ProxyRequestTimeout, which is far longer than this attempt's
	// share, so an empty map afterwards is the attempt's own doing and
	// not the cleanup ticker's.
	require.Greater(t, env.server.proxyManager.requestTimeout, pendingReleaseAttemptTimeout,
		"the periodic cleanup must not be able to clear the entry within the attempt's share")

	// The connector never delivers a reply, so the attempt can only end
	// at its own deadline.
	msg := &commands.ReplicaMessage{
		SenderEPubKey: []byte{1, 2, 3, 4},
		DEK:           &[60]byte{},
		Ciphertext:    []byte("proxied read"),
	}
	idHash := [32]byte{0xAA}

	start := time.Now()
	reply, err := env.inConn.sendProxyRequestSync(msg, &idHash, env.holders[0],
		nil, nil, replicaCommon.MKEMNikeScheme, pendingReleaseAttemptTimeout)
	require.Error(t, err, "an attempt no holder answers must not report success")
	require.Nil(t, reply)
	require.GreaterOrEqual(t, time.Since(start), pendingReleaseAttemptTimeout-time.Millisecond,
		"the attempt returned before its share expired, so it never really waited")

	require.Zero(t, pendingProxyRequests(env.server.proxyManager),
		"a timed-out attempt must drop its registration rather than leave it for the periodic cleanup")
}

// TestExhaustedProxySweepLeavesNothingPending is the same rule seen
// across a whole sweep: once every holder has been tried and the read
// has been answered, the manager holds nothing on that read's behalf.
func TestExhaustedProxySweepLeavesNothingPending(t *testing.T) {
	env := setupSemaScopeTestServer(t)
	env.server.cfg.ProxyRequestTimeout = int(pendingReleaseSweepBudget / time.Second)

	require.Greater(t, env.server.proxyManager.requestTimeout, pendingReleaseSweepBudget,
		"the periodic cleanup must not be able to clear the entries within the sweep")

	// A box this server does not shard, so serving the read means
	// proxying it to holders that never answer.
	boxID := findBoxByShardMembership(t, env.server, env.doc, false)
	proxyMsg := semaScopeValidReplicaMessage(t, env.server, boxID)

	_, ok := env.inConn.onReplicaCommand(proxyMsg, env.emitter)
	require.True(t, ok)

	select {
	case req := <-env.dummyOut:
		require.NotNil(t, req.ReplicaMessageReply, "expected a ReplicaMessageReply to be emitted")
		require.Equal(t, pigeonhole.ReplicaErrorReplicationFailed, req.ReplicaMessageReply.ErrorCode,
			"a sweep no holder answered must say so rather than answer as if it had")
	case <-time.After(pendingReleaseSweepBudget + sweepDeadlineSlack):
		t.Fatal("the proxied read never returned")
	}

	require.Zero(t, pendingProxyRequests(env.server.proxyManager),
		"an exhausted sweep must leave no registration behind for any holder it tried")
}

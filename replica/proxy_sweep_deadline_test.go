// SPDX-FileCopyrightText: Copyright (C) 2026 Katzenpost Contributors
// SPDX-License-Identifier: AGPL-3.0-only

package replica

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/pigeonhole"
	replicaCommon "github.com/katzenpost/katzenpost/replica/common"
)

// sweepDeadlineBudget is the whole-sweep budget these tests hand a
// request that will spend all of it queueing for a proxy worker slot.
// Nothing on that path performs a CTIDH1024 operation, so the budget
// only has to be long enough to tell a deliberate wait apart from an
// immediate return.
const sweepDeadlineBudget = 2 * time.Second

// sweepDeadlineSlack is how far past its budget a bounded attempt may
// return before these tests call it unbounded. A loaded runner may
// schedule a timer late and the honest work either side of the wait is
// CTIDH1024, so the margin is generous: the regression being caught is
// a wait that never ends at all, not one that ends untidily.
const sweepDeadlineSlack = 30 * time.Second

// TestProxySlotAcquireIsBoundedBySweepDeadline pins the rule that the
// wait for a proxy worker slot is spent from the sweep budget rather
// than before it.
//
// An unbounded acquire put the queueing delay outside the budget
// entirely: a saturated pool could hold a request for as long as it
// liked and then still grant it the attempt timeout computed before
// the wait began, so the client waited semaphore queue plus MKEM plus
// ProxyRequestTimeout for a budget that promises ProxyRequestTimeout.
// With the pool saturated by a slot nothing will release, the attempt
// must give up when the deadline passes and hand back no slot.
func TestProxySlotAcquireIsBoundedBySweepDeadline(t *testing.T) {
	env := setupSemaScopeTestServer(t)

	// Occupy the only proxy worker slot. Unlike the head-of-line
	// blocking tests there is no in-flight request to release it, so
	// the deadline is the sole way out.
	env.server.proxySema <- struct{}{}
	defer func() { <-env.server.proxySema }()

	replicaEpoch, _, _ := replicaCommon.ReplicaNow()
	deadline := time.Now().Add(sweepDeadlineBudget)

	type attempt struct {
		err     error
		elapsed time.Duration
	}
	done := make(chan attempt, 1)
	go func() {
		start := time.Now()
		_, _, _, err := env.inConn.proxyToShardWithSlot(env.holders[0], replicaEpoch,
			sweepDeadlineReadBlob(t, env), replicaCommon.MKEMNikeScheme, replicaCommon.NikeScheme,
			deadline, 1)
		done <- attempt{err: err, elapsed: time.Since(start)}
	}()

	select {
	case got := <-done:
		require.ErrorIs(t, got.err, errProxySweepBudgetExhausted,
			"an attempt that never won a slot must report an exhausted budget")
		require.GreaterOrEqual(t, got.elapsed, sweepDeadlineBudget-time.Millisecond,
			"the attempt returned before its budget expired, so it never really waited")
	case <-time.After(sweepDeadlineBudget + sweepDeadlineSlack):
		t.Fatal("the attempt is still queueing for a proxy worker slot past its sweep deadline")
	}

	require.Equal(t, 1, len(env.server.proxySema),
		"a timed-out acquire must leave the pool exactly as it found it")
}

// TestProxySweepEndsWithinBudgetUnderSaturation is the same rule seen
// from the client's side: a proxied read arriving at a replica whose
// proxy worker pool is saturated must come back with an error inside
// ProxyRequestTimeout, rather than queueing behind the pool until a
// slot happens to free up.
func TestProxySweepEndsWithinBudgetUnderSaturation(t *testing.T) {
	env := setupSemaScopeTestServer(t)
	env.server.cfg.ProxyRequestTimeout = int(sweepDeadlineBudget / time.Second)

	env.server.proxySema <- struct{}{}
	defer func() { <-env.server.proxySema }()

	// A box this server does not shard, so serving the read means
	// proxying it to a holder, which means taking a slot that will
	// never come free.
	boxID := findBoxByShardMembership(t, env.server, env.doc, false)
	proxyMsg := semaScopeValidReplicaMessage(t, env.server, boxID)

	_, ok := env.inConn.onReplicaCommand(proxyMsg, env.emitter)
	require.True(t, ok)

	select {
	case req := <-env.dummyOut:
		require.NotNil(t, req.ReplicaMessageReply, "expected a ReplicaMessageReply to be emitted")
		require.Equal(t, pigeonhole.ReplicaErrorReplicationFailed, req.ReplicaMessageReply.ErrorCode,
			"a sweep that reached no holder must say so rather than answer as if it had")
	case <-time.After(sweepDeadlineBudget + sweepDeadlineSlack):
		t.Fatal("the proxied read never returned: the sweep is waiting on the proxy worker pool outside its budget")
	}

	require.Equal(t, 1, len(env.server.proxySema),
		"the sweep must not have taken the pinned slot")
}

// sweepDeadlineReadBlob builds the padded inner message a proxied read
// carries, so an attempt can be driven directly rather than through a
// whole ReplicaMessage.
func sweepDeadlineReadBlob(t *testing.T, env *semaScopeTestEnv) []byte {
	t.Helper()
	var boxID [32]byte
	blob, err := pigeonhole.PadInnerMessageForEncryption(&pigeonhole.ReplicaInnerMessage{
		ReadMsg: &pigeonhole.ReplicaRead{BoxID: boxID},
	}, env.server.pigeonholeGeo)
	require.NoError(t, err)
	return blob
}

// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package localnet_test

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/hash"

	"github.com/katzenpost/katzenpost/client/localnet"
	"github.com/katzenpost/katzenpost/pigeonservice/common"
)

func testCtx(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	t.Cleanup(cancel)
	return ctx
}

// TestPlainARQ sends payloads to an echo service through the real daemon
// and the network's gateway, and gets each back.
func TestPlainARQ(t *testing.T) {
	n := localnet.New(t)
	n.AddHandler("echo", nil, bytes.Clone)
	n.Start()

	c := n.ThinClient()
	svc, err := c.GetService("echo")
	require.NoError(t, err)
	node := hash.Sum256(svc.MixDescriptor.IdentityKey)
	ctx := testCtx(t)
	for _, payload := range [][]byte{[]byte("plain ARQ one"), []byte("plain ARQ two")} {
		reply, err := c.StartResendingMessage(ctx, &node, svc.RecipientQueueID, payload)
		require.NoError(t, err)
		require.GreaterOrEqual(t, len(reply), len(payload))
		require.Equal(t, payload, reply[:len(payload)])
	}
}

// TestPigeonholeRoundTrip writes boxes through the real daemon, courier
// and replicas and reads them back.
func TestPigeonholeRoundTrip(t *testing.T) {
	n := localnet.New(t)
	n.AddStorage(3)
	n.Start()

	ph := common.NewThinPigeonhole(n.ThinClient())
	ctx := testCtx(t)
	wc, rc, first, err := ph.NewStream()
	require.NoError(t, err)
	idx := first
	for _, m := range []string{"first box", "second box"} {
		idx, err = common.WriteRetry(ctx, ph, wc, idx, []byte(m))
		require.NoError(t, err)
	}
	idx = first
	for _, m := range []string{"first box", "second box"} {
		var got []byte
		got, idx, err = common.ReadWait(ctx, ph, rc, idx, 100*time.Millisecond)
		require.NoError(t, err)
		require.Equal(t, m, string(got))
	}
}

// TestRedialAfterDrop drops the daemon's link to the gateway and shows the
// daemon redials it from the consensus and still completes a round trip.
func TestRedialAfterDrop(t *testing.T) {
	n := localnet.New(t)
	n.AddHandler("echo", nil, bytes.Clone)
	n.Start()

	c := n.ThinClient()
	svc, err := c.GetService("echo")
	require.NoError(t, err)
	node := hash.Sum256(svc.MixDescriptor.IdentityKey)

	n.DropGatewayLinks()

	// The daemon redials 2s after a drop and backs off to 17s after a
	// failed dial, so 15s is enough only if the first redial succeeds.
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	payload := []byte("after the drop")
	reply, err := c.StartResendingMessage(ctx, &node, svc.RecipientQueueID, payload)
	require.NoError(t, err)
	require.GreaterOrEqual(t, len(reply), len(payload))
	require.Equal(t, payload, reply[:len(payload)])
}

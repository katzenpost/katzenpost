// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package replica

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/log"
)

// FailPeer must fail only the requests targeting the dead peer, and a
// waiter on a failed request must observe a nil reply immediately.
func TestProxyManagerFailPeer(t *testing.T) {
	t.Parallel()

	backendLog, err := log.New("", "ERROR", false)
	require.NoError(t, err)

	m := NewProxyRequestManager(backendLog.GetLogger("test"), time.Minute)
	defer m.Shutdown()

	peerA := [32]byte{1}
	peerB := [32]byte{2}
	hashA := [32]byte{0xaa}
	hashB := [32]byte{0xbb}

	chA := m.RegisterProxyRequest(hashA, nil, nil, nil, peerA, "storagereplicaA")
	chB := m.RegisterProxyRequest(hashB, nil, nil, nil, peerB, "storagereplicaB")

	m.FailPeer(peerA)

	select {
	case reply, ok := <-chA:
		require.Nil(t, reply)
		require.False(t, ok)
	case <-time.After(time.Second):
		t.Fatal("waiter on failed peer did not observe closure")
	}

	select {
	case <-chB:
		t.Fatal("unrelated peer's request must stay pending")
	default:
	}
}

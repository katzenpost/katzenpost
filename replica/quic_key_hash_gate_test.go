// SPDX-License-Identifier: AGPL-3.0-only

package replica

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	authconfig "github.com/katzenpost/katzenpost/authority/voting/server/config"
	"github.com/katzenpost/katzenpost/core/pki"
)

func replicaDescriptorUnder(t *testing.T, total, withHash int) *pki.ReplicaDescriptor {
	t.Helper()
	client := &mockReplicaPKIClient{}
	w, cleanup := createPublishDescriptorTestWorker(t, client)
	t.Cleanup(cleanup)
	authorities := make([]*authconfig.Authority, total)
	for i := range authorities {
		authorities[i] = &authconfig.Authority{Identifier: fmt.Sprintf("auth%d", i+1)}
		if i < withHash {
			authorities[i].QUICKeyHash = bytes.Repeat([]byte{byte(i + 1)}, pki.QUICKeyHashSize)
		}
	}
	w.server.cfg.PKI.Voting.Authorities = authorities
	w.descAddrMap[pki.TransportQUIC] = []string{"quic://127.0.0.1:7483"}
	require.NoError(t, w.publishDescriptorIfNeeded(context.Background()))
	_, descriptors := client.posts()
	require.Len(t, descriptors, 1)
	return descriptors[0]
}

func TestReplicaPublishesItsQUICKeyHashWhenEveryAuthorityHasOne(t *testing.T) {
	setReplicaEpochClock(t, 1000, time.Second)
	desc := replicaDescriptorUnder(t, 3, 3)
	require.Len(t, desc.QUICKeyHash, 3*sha256.Size, "a replica withheld its QUIC key hash though every authority has a QUICKeyHash")
}

func TestReplicaWithholdsItsQUICKeyHashUnlessEveryAuthorityHasOne(t *testing.T) {
	setReplicaEpochClock(t, 1000, time.Second)
	for _, withHash := range []int{0, 2} {
		desc := replicaDescriptorUnder(t, 3, withHash)
		require.Nil(t, desc.QUICKeyHash, "a replica published its QUIC key hash with %d of 3 authorities pinned", withHash)
	}
	desc := replicaDescriptorUnder(t, 0, 0)
	require.Nil(t, desc.QUICKeyHash, "a replica published its QUIC key hash with no authorities configured")
}

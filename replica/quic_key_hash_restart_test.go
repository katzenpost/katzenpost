// SPDX-License-Identifier: AGPL-3.0-only

package replica

import (
	"bytes"
	"context"
	"crypto/sha256"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/pki"
)

type servingReplicaPKIClient struct {
	mockReplicaPKIClient
	doc  *pki.Document
	gets int
}

func (m *servingReplicaPKIClient) GetPKIDocumentForEpoch(_ context.Context, epoch uint64) (*pki.Document, []byte, error) {
	m.gets++
	if m.doc != nil && epoch == m.doc.Epoch {
		return m.doc, nil, nil
	}
	return nil, nil, pki.ErrNoDocument
}

func publishReplicaAfterRestart(t *testing.T, client *servingReplicaPKIClient) *pki.ReplicaDescriptor {
	t.Helper()
	w, cleanup := createPublishDescriptorTestWorker(t, client)
	defer cleanup()
	w.server.cfg.PublishQUICKeyHashes = true
	w.descAddrMap[pki.TransportQUIC] = []string{"quic://127.0.0.1:7483"}
	require.NoError(t, w.publishDescriptorIfNeeded(context.Background()))
	require.Len(t, client.descriptors, 1)
	return client.descriptors[0]
}

func TestRestartedReplicaPublishesItsKeyHashWhenTheConsensusIsFetchable(t *testing.T) {
	setReplicaEpochClock(t, 1000, time.Second)
	client := &servingReplicaPKIClient{doc: &pki.Document{
		Epoch:                  1000,
		AuthorityQUICKeyHashes: map[[pki.PublicKeyHashSize]byte][]byte{{1}: bytes.Repeat([]byte{2}, 3*pki.QUICKeyHashSize)},
	}}
	desc := publishReplicaAfterRestart(t, client)
	require.Len(t, desc.QUICKeyHash, 3*sha256.Size, "a restarted replica published its descriptor for epoch %d without its QUIC key hash; the consensus for 1000 with AuthorityQUICKeyHashes was fetchable (fetches made: %d)", desc.Epoch, client.gets)
}

func TestRestartedReplicaAtGenesisPublishesWithoutAKeyHash(t *testing.T) {
	setReplicaEpochClock(t, 1000, time.Second)
	client := &servingReplicaPKIClient{}
	desc := publishReplicaAfterRestart(t, client)
	require.Empty(t, desc.QUICKeyHash)
	require.Equal(t, 1, client.gets)
}

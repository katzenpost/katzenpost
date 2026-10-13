// SPDX-License-Identifier: AGPL-3.0-only

package replica

import (
	"bytes"
	"context"
	"crypto/sha256"
	"net/url"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/quic/common"
)

func publishedReplicaDescriptor(t *testing.T, quicAddresses []string, pinned bool) (*pki.ReplicaDescriptor, *PKIWorker) {
	t.Helper()
	client := &mockReplicaPKIClient{}
	w, cleanup := createPublishDescriptorTestWorker(t, client)
	t.Cleanup(cleanup)
	if pinned {
		for _, a := range w.server.cfg.PKI.Voting.Authorities {
			a.QUICKeyHash = bytes.Repeat([]byte{2}, pki.QUICKeyHashSize)
		}
	}
	if len(quicAddresses) > 0 {
		w.descAddrMap[pki.TransportQUIC] = quicAddresses
	}
	require.NoError(t, w.publishDescriptorIfNeeded(context.Background()))
	_, descriptors := client.posts()
	require.Len(t, descriptors, 1)
	return descriptors[0], w
}

func TestReplicaQUICKeyHash(t *testing.T) {
	setReplicaEpochClock(t, 1000, time.Second)
	desc, _ := publishedReplicaDescriptor(t, nil, true)
	require.Nil(t, desc.QUICKeyHash)

	desc, w := publishedReplicaDescriptor(t, []string{"quic://127.0.0.1:7483"}, true)
	l, err := common.ListenWithEpochKeys("127.0.0.1:0", w.server.identityPrivateKey, w.server.quicKeys, nil)
	require.NoError(t, err)
	defer l.Close()
	u, err := url.Parse("quic://" + l.Addr().String())
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := common.DialURL(u, ctx, nil, nil, nil)
	require.NoError(t, err)
	defer conn.Close()
	want := sha256.Sum256(conn.(*common.QuicConn).Conn.ConnectionState().TLS.PeerCertificates[0].RawSubjectPublicKeyInfo)
	require.Len(t, desc.QUICKeyHash, 3*sha256.Size)
	require.Equal(t, want[:], desc.QUICKeyHash[:sha256.Size], "the listener in epoch %d must present the first key the descriptor for %d publishes", desc.Epoch-1, desc.Epoch)
}

func TestReplicaPublishesNoQUICKeyHashWithoutAuthorityPins(t *testing.T) {
	setReplicaEpochClock(t, 1000, time.Second)
	desc, _ := publishedReplicaDescriptor(t, []string{"quic://127.0.0.1:7483"}, false)
	require.Nil(t, desc.QUICKeyHash, "a replica published its QUIC key hash without authority pins")
}

func TestReplicaPublishesThreeEpochKeyHashes(t *testing.T) {
	setReplicaEpochClock(t, 1000, time.Second)
	desc, _ := publishedReplicaDescriptor(t, []string{"quic://127.0.0.1:7483"}, true)
	require.Len(t, desc.QUICKeyHash, 3*sha256.Size, "the descriptor for epoch %d must carry the hashes of the keys for %d, %d and %d", desc.Epoch, desc.Epoch-1, desc.Epoch, desc.Epoch+1)
}

// SPDX-License-Identifier: AGPL-3.0-only

package replica

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	nikeschemes "github.com/katzenpost/hpqc/nike/schemes"

	"github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
)

type geometryPKIClient struct {
	mockReplicaPKIClient
	hash []byte
}

func (m *geometryPKIClient) GetPKIDocumentForEpoch(ctx context.Context, epoch uint64) (*pki.Document, []byte, error) {
	doc := &pki.Document{Epoch: epoch, SphinxGeometryHash: m.hash}
	raw, err := doc.MarshalCertificate()
	return doc, raw, err
}

func TestFetchAndProcessDocumentsRejectsForeignGeometry(t *testing.T) {
	foreign := geo.GeometryFromUserForwardPayloadLength(nikeschemes.ByName("x25519"), 3000, true, 5)
	client := &geometryPKIClient{hash: foreign.Hash()}
	p, cleanup := createPublishDescriptorTestWorker(t, client)
	defer cleanup()
	require.NotEqual(t, p.server.cfg.SphinxGeometry.Hash(), foreign.Hash())

	epochs := p.DocumentsToFetch()
	require.NotEmpty(t, epochs)
	notCanceled := func() bool { return false }

	require.False(t, p.fetchAndProcessDocuments(context.Background(), notCanceled))
	for _, epoch := range epochs {
		require.Nil(t, p.EntryForEpoch(epoch))
	}

	client.hash = p.server.cfg.SphinxGeometry.Hash()
	require.True(t, p.fetchAndProcessDocuments(context.Background(), notCanceled))
	for _, epoch := range epochs {
		require.NotNil(t, p.EntryForEpoch(epoch))
	}
}

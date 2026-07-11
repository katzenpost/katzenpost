// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	dirauthconfig "github.com/katzenpost/katzenpost/authority/voting/server/config"
	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/katzenpost/katzenpost/courier/server/config"
)

// goneRecordingClient records every epoch it is asked to fetch and always
// reports the document gone, simulating a consensus gap.
type goneRecordingClient struct {
	mu  sync.Mutex
	req []uint64
}

func (m *goneRecordingClient) GetPKIDocumentForEpoch(ctx context.Context, epoch uint64) (*pki.Document, []byte, error) {
	m.mu.Lock()
	m.req = append(m.req, epoch)
	m.mu.Unlock()
	return nil, nil, pki.ErrDocumentGone
}

func (m *goneRecordingClient) reset() {
	m.mu.Lock()
	m.req = nil
	m.mu.Unlock()
}

func (m *goneRecordingClient) requested(epoch uint64) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, e := range m.req {
		if e == epoch {
			return true
		}
	}
	return false
}

func newTestCourierPKIWorker(t *testing.T, client pki.Fetcher) *PKIWorker {
	g := &geo.Geometry{
		PacketLength:                3082,
		HeaderLength:                476,
		RoutingInfoLength:           410,
		PerHopRoutingInfoLength:     82,
		SURBLength:                  572,
		SphinxPlaintextHeaderLength: 2,
		PayloadTagLength:            32,
		ForwardPayloadLength:        2574,
		UserForwardPayloadLength:    2000,
		NextNodeHopLength:           65,
		SPRPKeyMaterialLength:       64,
		NIKEName:                    "X25519",
	}
	backendLog, err := log.New("", "ERROR", false)
	require.NoError(t, err)
	server := &Server{
		cfg: &config.Config{
			SphinxGeometry: g,
			WireKEMScheme:  "Xwing",
			PKIScheme:      "ed25519",
			EnvelopeScheme: "CTIDH1024-X25519",
			PKI: &config.PKI{
				Voting: &config.Voting{
					Authorities: []*dirauthconfig.Authority{{}},
				},
			},
		},
		logBackend: backendLog,
	}
	server.log = server.logBackend.GetLogger("courier-server")
	w, err := newPKIWorker(server, client, server.logBackend.GetLogger("courier-pkiworker"))
	require.NoError(t, err)
	return w
}

// TestFetchDocumentsDoesNotRecrawlGoneEpochs pins the fix to the "crawl GC'd
// epochs" behavior: when the courier has no current PKI document it may retry
// only the CURRENT epoch (its consensus might have been published late), but it
// must NOT keep re-requesting now-1 / now-2, which the authorities have
// permanently garbage-collected. Re-crawling those wastes fetches and widens
// the window for a slow fetch to stall the worker.
func TestFetchDocumentsDoesNotRecrawlGoneEpochs(t *testing.T) {
	client := &goneRecordingClient{}
	w := newTestCourierPKIWorker(t, client)

	ctx := context.Background()
	noCancel := func() bool { return false }
	now, _, _ := epochtime.Now()

	// First cycle: nothing is cached, so every epoch in the fetch window is
	// requested and comes back gone, which marks it as failed.
	w.fetchDocuments(ctx, noCancel)
	require.True(t, client.requested(now-1), "first cycle must try now-1")
	require.True(t, client.requested(now-2), "first cycle must try now-2")

	// Second cycle: the past epochs are marked gone and must be skipped; only
	// the current epoch (whose mark the courier clears) may be re-requested.
	client.reset()
	w.fetchDocuments(ctx, noCancel)
	require.False(t, client.requested(now-1), "now-1 is GC'd; it must not be re-crawled")
	require.False(t, client.requested(now-2), "now-2 is GC'd; it must not be re-crawled")
	require.True(t, client.requested(now), "the current epoch should still be retried")
}

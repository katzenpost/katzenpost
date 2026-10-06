// SPDX-License-Identifier: AGPL-3.0-only

package pki

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/op/go-logging.v1"

	"github.com/katzenpost/katzenpost/core/epochtime"
	cpki "github.com/katzenpost/katzenpost/core/pki"
)

func TestGatewayConsensusAnswersPerWindow(t *testing.T) {
	now, _, _ := epochtime.Now()
	p := &pki{
		log:           logging.MustGetLogger("pki"),
		rawDocs:       map[uint64][]byte{now - 1: []byte("previous"), now: []byte("current"), now + 1: []byte("next")},
		failedFetches: map[uint64]error{},
	}

	for _, e := range []uint64{now - 1, now, now + 1} {
		raw, err := p.GetRawConsensus(e)
		require.NoError(t, err, "epoch %d held", e)
		require.Equal(t, p.rawDocs[e], raw)
	}

	for _, e := range []uint64{now - 2, now - 10} {
		_, err := p.GetRawConsensus(e)
		require.ErrorIs(t, err, cpki.ErrNoDocument, "epoch %d below N-1", e)
	}

	delete(p.rawDocs, now)
	delete(p.rawDocs, now+1)
	for _, e := range []uint64{now, now + 1, now + 2} {
		_, err := p.GetRawConsensus(e)
		require.Error(t, err)
		require.NotErrorIs(t, err, cpki.ErrNoDocument, "epoch %d not held", e)
	}

	p.noteFetchFailure(now+1, fmt.Errorf("fetch: %w", cpki.ErrDocumentGone))
	_, err := p.GetRawConsensus(now + 1)
	require.ErrorIs(t, err, cpki.ErrNoDocument, "epoch answered Gone")
	p.rawDocs[now+1] = []byte("next")
	_, err = p.GetRawConsensus(now + 1)
	require.ErrorIs(t, err, cpki.ErrNoDocument, "a Gone mark is final even if a document arrives")

	p.noteFetchFailure(now, cpki.ErrNoDocument)
	_, err = p.GetRawConsensus(now)
	require.NotErrorIs(t, err, cpki.ErrNoDocument, "only Gone is final")
}

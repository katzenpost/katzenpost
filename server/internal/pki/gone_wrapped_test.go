// SPDX-License-Identifier: AGPL-3.0-only

package pki

import (
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/log"
	cpki "github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/server/internal/pkicache"
)

func TestWorkerCachesWrappedGone(t *testing.T) {
	backend, err := log.New("", "ERROR", false)
	require.NoError(t, err)
	p := &pki{
		log:           backend.GetLogger("pki"),
		docs:          make(map[uint64]*pkicache.Entry),
		rawDocs:       make(map[uint64][]byte),
		failedFetches: make(map[uint64]error),
	}
	p.noteFetchFailure(5, fmt.Errorf("authority auth1: %w", cpki.ErrDocumentGone))
	failed, ferr := p.getFailedFetch(5)
	require.True(t, failed)
	require.ErrorIs(t, ferr, cpki.ErrDocumentGone)

	p.noteFetchFailure(6, errors.New("dial tcp: connection refused"))
	failed, _ = p.getFailedFetch(6)
	require.False(t, failed)
}

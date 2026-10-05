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

func TestWorkerCachesOnlyGoneHoweverWrapped(t *testing.T) {
	backend, err := log.New("", "ERROR", false)
	require.NoError(t, err)
	p := &pki{log: backend.GetLogger("pki"), failedFetches: make(map[uint64]error)}

	for epoch, err := range map[uint64]error{
		1: fmt.Errorf("outer: %w", fmt.Errorf("auth1: %w", cpki.ErrDocumentGone)),
		2: errors.Join(errors.New("auth1: timeout"), cpki.ErrDocumentGone),
	} {
		p.noteFetchFailure(epoch, err)
		failed, ferr := p.getFailedFetch(epoch)
		require.True(t, failed, epoch)
		require.Same(t, err, ferr)
	}
	for epoch, err := range map[uint64]error{
		3: fmt.Errorf("auth1: %w", cpki.ErrNoDocument),
		4: cpki.ErrNoDocument,
		5: errors.New(cpki.ErrDocumentGone.Error()),
	} {
		p.noteFetchFailure(epoch, err)
		failed, _ := p.getFailedFetch(epoch)
		require.False(t, failed, epoch)
	}
}

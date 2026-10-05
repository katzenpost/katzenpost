// SPDX-License-Identifier: AGPL-3.0-only

package pki

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/log"
)

type errFetcher struct{ err error }

func (f errFetcher) GetPKIDocumentForEpoch(context.Context, uint64) (*Document, []byte, error) {
	return nil, nil, f.err
}

func failedFetches(t *testing.T, fetchErr error) map[uint64]error {
	backend, err := log.New("", "ERROR", false)
	require.NoError(t, err)
	failed := make(map[uint64]error)
	NewDocumentFetcher(errFetcher{fetchErr}, backend.GetLogger("test")).FetchDocuments(
		context.Background(),
		[]uint64{7},
		func() bool { return false },
		func(uint64) (bool, error) { return false, nil },
		func(e uint64, err error) { failed[e] = err },
	)
	return failed
}

func TestFetcherCachesWrappedGone(t *testing.T) {
	wrapped := fmt.Errorf("authority auth1: %w", ErrDocumentGone)
	require.ErrorIs(t, failedFetches(t, wrapped)[7], ErrDocumentGone)
	require.ErrorIs(t, failedFetches(t, ErrDocumentGone)[7], ErrDocumentGone)
}

func TestFetcherRetriesOtherErrors(t *testing.T) {
	require.Empty(t, failedFetches(t, errors.New("dial tcp: connection refused")))
	require.Empty(t, failedFetches(t, fmt.Errorf("x: %w", ErrNoDocument)))
}

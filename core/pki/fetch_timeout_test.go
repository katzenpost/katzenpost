// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package pki

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/epochtime/periodtest"
	"github.com/katzenpost/katzenpost/core/log"
)

// blockingFetcher models a PKI fetch that only returns when its context is
// cancelled — e.g. a GetPKIDocumentForEpoch whose per-authority fetchers are
// unblocked solely by context cancellation (an unreachable or retrying dirauth
// during a consensus gap). If the worker hands such a fetch a context that
// never cancels, the fetch — and thus the whole worker loop — wedges: it stops
// advancing to the current epoch until the process is restarted.
type blockingFetcher struct{}

func (blockingFetcher) GetPKIDocumentForEpoch(ctx context.Context, epoch uint64) (*Document, []byte, error) {
	<-ctx.Done()
	return nil, nil, ctx.Err()
}

// TestFetchDocumentsBoundsFetchCycle pins the wedge: a single fetch cycle must
// be bounded even when the worker's own context (SetupWorkerContext, which only
// cancels on halt) never times out. Before the fix, FetchDocuments passes that
// never-cancelling context straight to the fetcher, so a fetch that only
// returns on cancellation blocks the cycle forever. After the fix, the cycle
// carries its own FetchTimeout and always returns.
func TestFetchDocumentsBoundsFetchCycle(t *testing.T) {
	periodtest.Run(t, func(t *testing.T, p time.Duration) {
		if p != 2*time.Minute {
			return
		}
		backend, err := log.New("", "ERROR", false)
		require.NoError(t, err)

		w := NewWorkerBase(blockingFetcher{}, backend.GetLogger("test"))

		// A worker context that only cancels on halt - exactly what
		// SetupWorkerContext produces in production. It never times out.
		halt := make(chan interface{})
		defer close(halt)
		pkiCtx, cancelFn, isCanceled := SetupWorkerContext(halt, backend.GetLogger("ctx"))
		defer cancelFn()

		done := make(chan struct{})
		go func() {
			w.FetchDocuments(pkiCtx, isCanceled)
			close(done)
		}()

		select {
		case <-done:
			// FetchDocuments bounded its own cycle and returned despite a fetcher
			// that never returns on its own.
		case <-time.After(p/8 + 2*time.Second):
			t.Fatal("FetchDocuments did not return: the PKI worker fetch cycle is unbounded (wedge)")
		}
	})
}

type deadlineFetcher struct{ left chan time.Duration }

func (f deadlineFetcher) GetPKIDocumentForEpoch(ctx context.Context, epoch uint64) (*Document, []byte, error) {
	d, ok := ctx.Deadline()
	if !ok {
		f.left <- -1
		return nil, nil, ErrNoDocument
	}
	f.left <- time.Until(d)
	return nil, nil, ErrNoDocument
}

func TestFetchCycleEndsWithinOnePhase(t *testing.T) {
	periodtest.Run(t, func(t *testing.T, p time.Duration) {
		backend, err := log.New("", "ERROR", false)
		require.NoError(t, err)
		f := deadlineFetcher{left: make(chan time.Duration, NumPKIDocsToFetch+1)}
		w := NewWorkerBase(f, backend.GetLogger("test"))
		w.FetchDocuments(context.Background(), func() bool { return false })
		close(f.left)
		n := 0
		for left := range f.left {
			n++
			require.Greater(t, left, time.Duration(0))
			require.LessOrEqual(t, left, min(3*time.Minute, p/8))
		}
		require.NotZero(t, n)
	})
}

// SPDX-License-Identifier: AGPL-3.0-only

package pki

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/sign"

	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/log"
	cpki "github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/loops"
	"github.com/katzenpost/katzenpost/server/internal/pkicache"
)

type failingFetcher struct {
	sync.Mutex
	calls map[uint64]int
}

func (f *failingFetcher) GetPKIDocumentForEpoch(_ context.Context, epoch uint64) (*cpki.Document, []byte, error) {
	f.Lock()
	f.calls[epoch]++
	f.Unlock()
	if epoch%2 == 0 {
		return nil, nil, fmt.Errorf("authority auth1: %w", cpki.ErrDocumentGone)
	}
	return nil, nil, fmt.Errorf("authority auth1: %w", cpki.ErrNoDocument)
}

func (f *failingFetcher) Post(context.Context, uint64, sign.PrivateKey, sign.PublicKey, *cpki.MixDescriptor, *loops.LoopStats) error {
	return nil
}

func (f *failingFetcher) seen() map[uint64]int {
	f.Lock()
	defer f.Unlock()
	m := make(map[uint64]int, len(f.calls))
	for k, v := range f.calls {
		m[k] = v
	}
	return m
}

func TestWorkerCachesOnlyWrappedGoneFromFetch(t *testing.T) {
	backend, err := log.New("", "ERROR", false)
	require.NoError(t, err)
	g := &rotationGlue{mk: &fakeMixKeys{}}
	f := &failingFetcher{calls: make(map[uint64]int)}
	p := &pki{
		glue:          g,
		log:           backend.GetLogger("pki"),
		impl:          f,
		docs:          make(map[uint64]*pkicache.Entry),
		rawDocs:       make(map[uint64][]byte),
		failedFetches: make(map[uint64]error),
	}
	p.StartWorker()
	defer p.Halt()

	deadline := time.Now().Add(epochtime.Period()/64 + 30*time.Second)
	for {
		var gone, other int
		for epoch := range f.seen() {
			if epoch%2 == 1 {
				other++
				failed, _ := p.getFailedFetch(epoch)
				require.False(t, failed, epoch)
				continue
			}
			if failed, ferr := p.getFailedFetch(epoch); failed {
				require.ErrorIs(t, ferr, cpki.ErrDocumentGone)
				gone++
			}
		}
		if gone > 0 && other > 0 {
			return
		}
		require.True(t, time.Now().Before(deadline), "worker never cached a gone epoch")
		time.Sleep(50 * time.Millisecond)
	}
}

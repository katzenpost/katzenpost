// SPDX-License-Identifier: AGPL-3.0-only

package client

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/client/config"
	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/log"
	cpki "github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/wire/commands"
)

type goneWorkerGetter struct {
	mockConsensusGetter
	mu    sync.Mutex
	calls map[uint64]int
}

func (g *goneWorkerGetter) GetConsensus(ctx context.Context, epoch uint64) (*commands.Consensus2, error) {
	g.mu.Lock()
	g.calls[epoch]++
	g.mu.Unlock()
	return g.mockConsensusGetter.GetConsensus(ctx, epoch)
}

func (g *goneWorkerGetter) count(epoch uint64) int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.calls[epoch]
}

func runPKIWorkerPasses(t *testing.T, pkiClient *mockPKIClient, getter *goneWorkerGetter) (*pki, uint64) {
	cfg, err := config.LoadFile(testClientTOML)
	require.NoError(t, err)
	cfg.Callbacks = &config.Callbacks{}
	logbackend, err := log.New("", "debug", false)
	require.NoError(t, err)
	c := &Client{logbackend: logbackend, cfg: cfg, PKIClient: pkiClient}
	p := newPKI(c)
	c.pki = p
	p.consensusGetter = getter
	p.Go(p.worker)
	epoch, _, _ := epochtime.Now()
	for range 3 {
		p.forceUpdateCh <- true
		require.Eventually(t, func() bool { return len(p.forceUpdateCh) == 0 }, 10*time.Second, time.Millisecond)
	}
	p.forceUpdateCh <- true
	require.Eventually(t, func() bool { return len(p.forceUpdateCh) == 0 }, 10*time.Second, time.Millisecond)
	p.Halt()
	return p, epoch
}

func TestPKIWorkerCachesGoneConsensus(t *testing.T) {
	getter := &goneWorkerGetter{
		mockConsensusGetter: mockConsensusGetter{errorCode: commands.ConsensusGone},
		calls:               make(map[uint64]int),
	}
	p, epoch := runPKIWorkerPasses(t, new(mockPKIClient), getter)
	require.ErrorIs(t, p.failedFetches[epoch], cpki.ErrDocumentGone)
	require.Equal(t, 1, getter.count(epoch))
}

func TestPKIWorkerRetriesBadReply(t *testing.T) {
	getter := &goneWorkerGetter{calls: make(map[uint64]int)}
	p, epoch := runPKIWorkerPasses(t, &mockPKIClient{deserializeErr: errors.New("bad signature")}, getter)
	require.NotContains(t, p.failedFetches, epoch)
	require.GreaterOrEqual(t, getter.count(epoch), 2)
}

func TestPKIWorkerFallbackHonoursGonePreviousEpoch(t *testing.T) {
	getter := &goneWorkerGetter{
		mockConsensusGetter: mockConsensusGetter{errorCode: commands.ConsensusGone},
		calls:               make(map[uint64]int),
	}
	_, epoch := runPKIWorkerPasses(t, new(mockPKIClient), getter)
	require.Equal(t, 1, getter.count(epoch-1))
}

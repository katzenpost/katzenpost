// SPDX-License-Identifier: AGPL-3.0-only

package client

import (
	"context"
	"encoding/binary"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/wire/commands"
)

type linkGatedGetter struct {
	conn     *connection
	mu       sync.Mutex
	attempts int
	served   map[uint64]int
}

func (g *linkGatedGetter) GetConsensus(ctx context.Context, epoch uint64) (*commands.Consensus2, error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.attempts++
	if !g.conn.isConnected.Load() {
		return nil, ErrNotConnected
	}
	g.served[epoch]++
	payload := make([]byte, 8)
	binary.BigEndian.PutUint64(payload, epoch)
	return &commands.Consensus2{ErrorCode: commands.ConsensusOk, Payload: payload}, nil
}

func (g *linkGatedGetter) counts(epoch uint64) (int, int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.attempts, g.served[epoch]
}

func TestPKIRefetchSurvivesAWakeBeforeTheLinkIsUp(t *testing.T) {
	epoch, _, _ := epochtime.Now()
	p, _ := newRefetchPKI(t, false, epoch, epoch+1)
	conn := newConnection(p.c)
	g := &linkGatedGetter{conn: conn, served: make(map[uint64]int)}
	p.consensusGetter = g
	p.Go(p.worker)
	require.Eventually(t, func() bool { a, _ := g.counts(epoch); return a >= 1 }, 5*time.Second, 10*time.Millisecond)
	time.Sleep(100 * time.Millisecond)

	before, _ := g.counts(epoch)
	p.setClockSkew(0)
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if a, _ := g.counts(epoch); a > before {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(100 * time.Millisecond)

	conn.onConnStatusChange(nil)
	require.Eventually(t, func() bool { _, s := g.counts(epoch); return s >= 1 }, 3*time.Second, 10*time.Millisecond)
}

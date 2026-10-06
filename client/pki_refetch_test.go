// SPDX-License-Identifier: AGPL-3.0-only

package client

import (
	"context"
	"encoding/binary"
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

type countingConsensusGetter struct {
	mu    sync.Mutex
	calls map[uint64]int
}

func (g *countingConsensusGetter) GetConsensus(ctx context.Context, epoch uint64) (*commands.Consensus2, error) {
	g.mu.Lock()
	g.calls[epoch]++
	g.mu.Unlock()
	payload := make([]byte, 8)
	binary.BigEndian.PutUint64(payload, epoch)
	return &commands.Consensus2{ErrorCode: commands.ConsensusOk, Payload: payload}, nil
}

func (g *countingConsensusGetter) count(epoch uint64) int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.calls[epoch]
}

func (g *countingConsensusGetter) reset() {
	g.mu.Lock()
	g.calls = make(map[uint64]int)
	g.mu.Unlock()
}

type epochPKIClient struct {
	mockPKIClient
	geometryHash []byte
}

func (c *epochPKIClient) Deserialize(raw []byte) (*cpki.Document, error) {
	return &cpki.Document{Epoch: binary.BigEndian.Uint64(raw), SphinxGeometryHash: c.geometryHash}, nil
}

func newRefetchPKI(t *testing.T, timeSync bool, cached ...uint64) (*pki, *countingConsensusGetter) {
	cfg, err := config.LoadFile(testClientTOML)
	require.NoError(t, err)
	cfg.Callbacks = &config.Callbacks{}
	cfg.Debug.EnableTimeSync = timeSync
	logbackend, err := log.New("", "debug", false)
	require.NoError(t, err)
	c := &Client{
		logbackend: logbackend,
		cfg:        cfg,
		PKIClient:  &epochPKIClient{geometryHash: cfg.SphinxGeometry.Hash()},
	}
	p := newPKI(c)
	c.pki = p
	g := &countingConsensusGetter{calls: make(map[uint64]int)}
	p.consensusGetter = g
	for _, e := range cached {
		p.docs.Store(e, &CachedDoc{Doc: &cpki.Document{Epoch: e, SphinxGeometryHash: cfg.SphinxGeometry.Hash()}})
	}
	t.Cleanup(func() {
		p.Halt()
		p.Wait()
	})
	return p, g
}

func TestPKIWorkerRefetchesCachedDocumentOnReconnect(t *testing.T) {
	epoch, _, _ := epochtime.Now()
	p, g := newRefetchPKI(t, false, epoch, epoch+1)
	p.Go(p.worker)
	require.Eventually(t, func() bool { return g.count(epoch) >= 1 }, 5*time.Second, 10*time.Millisecond)

	g.reset()
	p.forceUpdateCh <- true
	time.Sleep(200 * time.Millisecond)
	require.Zero(t, g.count(epoch))

	p.onConnected()
	require.Eventually(t, func() bool { return g.count(epoch) >= 1 }, 5*time.Second, 10*time.Millisecond)
}

func waitPKIPass(t *testing.T, passes <-chan uint64) uint64 {
	t.Helper()
	select {
	case e := <-passes:
		return e
	case <-time.After(5 * time.Second):
		t.Fatal("the PKI worker did not finish a pass")
		return 0
	}
}

func TestPKIWorkerRefetchesCachedDocumentOnEpochChange(t *testing.T) {
	period := epochtime.Period()
	_, elapsed, _ := epochtime.Now()
	p, g := newRefetchPKI(t, true)
	p.clockSkew = -int64(((period - elapsed) + (period - nextFetchTill()/2)) / time.Second)
	epoch, _, till := epochtime.FromUnix(p.skewedUnixTime())
	require.Less(t, till, nextFetchTill())
	for _, e := range []uint64{epoch, epoch + 1, epoch + 2} {
		p.docs.Store(e, &CachedDoc{Doc: &cpki.Document{Epoch: e, SphinxGeometryHash: p.c.cfg.SphinxGeometry.Hash()}})
	}
	passes := make(chan uint64, 4)
	p.c.cfg.Callbacks.OnDocumentFn = func(d *cpki.Document) { passes <- d.Epoch }
	p.Go(p.worker)
	require.Equal(t, epoch, waitPKIPass(t, passes))
	require.Equal(t, 1, g.count(epoch))
	require.Equal(t, 1, g.count(epoch+1))

	g.reset()
	p.clockSkewLock.Lock()
	p.clockSkew -= int64(period / time.Second)
	p.clockSkewLock.Unlock()
	p.forceUpdateCh <- true
	require.Equal(t, epoch+1, waitPKIPass(t, passes))
	require.Equal(t, 1, g.count(epoch+1))
}

func TestPKIWorkerFetchesWithoutCache(t *testing.T) {
	epoch, _, _ := epochtime.Now()
	p, g := newRefetchPKI(t, false)
	p.Go(p.worker)
	require.Eventually(t, func() bool { return g.count(epoch) >= 1 }, 5*time.Second, 10*time.Millisecond)
	require.Eventually(t, func() bool { return p.GetDocumentByEpoch(epoch) != nil }, 5*time.Second, 10*time.Millisecond)
	require.Equal(t, 1, g.count(epoch))
}

func TestPKIWorkerKeepsVerifiedDocumentsAcrossTheBoundary(t *testing.T) {
	epoch, _, _ := epochtime.Now()
	p, g := newRefetchPKI(t, true)
	for _, e := range []uint64{epoch, epoch + 1, epoch + 2} {
		p.docs.Store(e, &CachedDoc{
			Doc:           &cpki.Document{Epoch: e, SphinxGeometryHash: p.c.cfg.SphinxGeometry.Hash()},
			Blob:          []byte("doc"),
			RawSignedBlob: []byte("signed"),
		})
	}
	p.Go(p.worker)
	p.forceUpdateCh <- true
	time.Sleep(200 * time.Millisecond)
	g.reset()

	p.clockSkewLock.Lock()
	p.clockSkew = -int64(epochtime.Period().Seconds())
	p.clockSkewLock.Unlock()
	p.forceUpdateCh <- true
	time.Sleep(300 * time.Millisecond)
	require.Zero(t, g.count(epoch+1))
	require.Zero(t, g.count(epoch+2))

	p.onConnected()
	require.Eventually(t, func() bool { return g.count(epoch+1) >= 1 }, 5*time.Second, 10*time.Millisecond)
}

// SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package client2

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/katzenpost/hpqc/rand"
	"github.com/katzenpost/hpqc/sign"

	"github.com/katzenpost/katzenpost/client2/config"
	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/log"
	cpki "github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/wire/commands"
	"github.com/katzenpost/katzenpost/loops"
	"github.com/stretchr/testify/require"
)

type mockConsensusGetter struct {
	// If set, returns this error code for all epochs.
	errorCode uint8
	// If set, overrides errorCode for specific epochs.
	epochErrors map[uint64]uint8
}

func (m *mockConsensusGetter) GetConsensus(ctx context.Context, epoch uint64) (*commands.Consensus2, error) {
	if m.epochErrors != nil {
		if code, ok := m.epochErrors[epoch]; ok {
			return &commands.Consensus2{ErrorCode: code}, nil
		}
	}
	return &commands.Consensus2{ErrorCode: m.errorCode}, nil
}

type mockPKIClient struct {
	doc *cpki.Document
}

func (c *mockPKIClient) PostReplica(ctx context.Context, epoch uint64, signingPrivateKey sign.PrivateKey, signingPublicKey sign.PublicKey, d *cpki.ReplicaDescriptor) error {
	panic("not implemented")
}

func (c *mockPKIClient) GetPKIDocumentForEpoch(ctx context.Context, epoch uint64) (*cpki.Document, []byte, error) {
	return nil, nil, nil
}

func (c *mockPKIClient) Post(ctx context.Context, epoch uint64, signingPrivateKey sign.PrivateKey, signingPublicKey sign.PublicKey, d *cpki.MixDescriptor, loopstats *loops.LoopStats) error {
	return nil
}

func (c *mockPKIClient) Deserialize(raw []byte) (*cpki.Document, error) {
	return c.doc, nil
}

func NoTestClientPKIStartStop(t *testing.T) {
	cfg, err := config.LoadFile("testdata/client.toml")
	require.NoError(t, err)

	myMockPKIClient := new(mockPKIClient)
	logbackend, err := log.New("", "debug", false)
	require.NoError(t, err)
	c := &Client{
		logbackend: logbackend,
		cfg:        cfg,
		PKIClient:  myMockPKIClient,
	}

	p := newPKI(c)
	p.consensusGetter = new(mockConsensusGetter)
	p.start()

	p.Halt()
	p.Wait()
}

func TestPKIGetDocument(t *testing.T) {
	cfg, err := config.LoadFile("testdata/client.toml")
	require.NoError(t, err)

	myMockPKIClient := new(mockPKIClient)
	logbackend, err := log.New("", "debug", false)
	require.NoError(t, err)
	c := &Client{
		logbackend: logbackend,
		cfg:        cfg,
		PKIClient:  myMockPKIClient,
	}

	p := newPKI(c)
	p.consensusGetter = new(mockConsensusGetter)

	epoch, _, _ := epochtime.Now()
	ctx := context.TODO()

	myMockPKIClient.doc = &cpki.Document{
		Epoch: epoch,
	}

	_, doc, err := p.getDocument(ctx, epoch)
	require.NoError(t, err)
	require.NotNil(t, doc)
	require.Equal(t, doc.Epoch, epoch)

	wrongEpoch := uint64(1234567)
	ctx = context.TODO()

	_, doc, err = p.getDocument(ctx, wrongEpoch)
	require.Error(t, err)
	require.Nil(t, doc)
}

func TestPKIUpdateDocumentBadSphinxHash(t *testing.T) {
	cfg, err := config.LoadFile("testdata/client.toml")
	require.NoError(t, err)

	myMockPKIClient := new(mockPKIClient)
	logbackend, err := log.New("", "debug", false)
	require.NoError(t, err)
	c := &Client{
		logbackend: logbackend,
		cfg:        cfg,
		PKIClient:  myMockPKIClient,
	}

	p := newPKI(c)
	p.consensusGetter = new(mockConsensusGetter)

	epoch, _, _ := epochtime.Now()

	sphinxHash := make([]byte, 32)
	_, err = rand.Reader.Read(sphinxHash)
	require.NoError(t, err)

	testDoc := &cpki.Document{
		Epoch:              epoch,
		SphinxGeometryHash: sphinxHash,
	}

	myMockPKIClient.doc = testDoc
	defer func() {
		if r := recover(); r == nil {
			t.Errorf("The code did not panic")
		}
	}()

	// panic with bad sphinx geometry hash
	err = p.updateDocument(epoch)
	require.Error(t, err)
}

func TestPKIUpdateDocument(t *testing.T) {
	cfg, err := config.LoadFile("testdata/client.toml")
	require.NoError(t, err)

	myMockPKIClient := new(mockPKIClient)
	logbackend, err := log.New("", "debug", false)
	require.NoError(t, err)
	c := &Client{
		logbackend: logbackend,
		cfg:        cfg,
		PKIClient:  myMockPKIClient,
	}

	p := newPKI(c)
	p.consensusGetter = new(mockConsensusGetter)

	epoch, _, _ := epochtime.Now()

	testDoc := &cpki.Document{
		Epoch:              epoch,
		SphinxGeometryHash: c.cfg.SphinxGeometry.Hash(),
	}

	myMockPKIClient.doc = testDoc
	_, currentDoc := p.currentDocument()
	require.Nil(t, currentDoc)

	// panic with bad sphinx geometry hash
	err = p.updateDocument(epoch)
	require.NoError(t, err)

	err = p.updateDocument(epoch)
	require.NoError(t, err)

	t.Log("currentDocument works if Sphinx Geometry Hash is correctly set:")
	_, doc := p.currentDocument()
	require.NotNil(t, doc)
	require.Equal(t, testDoc, doc)
}

func TestPKIWaitForDocument(t *testing.T) {
	cfg, err := config.LoadFile("testdata/client.toml")
	require.NoError(t, err)

	myMockPKIClient := new(mockPKIClient)
	logbackend, err := log.New("", "debug", false)
	require.NoError(t, err)
	c := &Client{
		logbackend: logbackend,
		cfg:        cfg,
		PKIClient:  myMockPKIClient,
	}

	p := newPKI(c)
	c.pki = p
	p.consensusGetter = new(mockConsensusGetter)

	epoch, _, _ := epochtime.Now()

	testDoc := &cpki.Document{
		Epoch:              epoch,
		SphinxGeometryHash: c.cfg.SphinxGeometry.Hash(),
	}

	myMockPKIClient.doc = testDoc

	_, currentDoc := p.currentDocument()
	require.Nil(t, currentDoc)
	c.WaitForCurrentDocument()
	_, currentDoc = p.currentDocument()
	require.NotNil(t, currentDoc)
	require.Equal(t, currentDoc, testDoc)
}

func TestPKIClockSkew(t *testing.T) {
	cfg, err := config.LoadFile("testdata/client.toml")
	require.NoError(t, err)

	myMockPKIClient := new(mockPKIClient)
	logbackend, err := log.New("", "debug", false)
	require.NoError(t, err)
	c := &Client{
		logbackend: logbackend,
		cfg:        cfg,
		PKIClient:  myMockPKIClient,
	}
	p := newPKI(c)
	c.pki = p
	p.consensusGetter = new(mockConsensusGetter)

	epoch, _, _ := epochtime.Now()
	ctx := context.TODO()

	myMockPKIClient.doc = &cpki.Document{
		Epoch: epoch,
	}

	_, doc, err := p.getDocument(ctx, epoch)
	require.NoError(t, err)
	require.NotNil(t, doc)
	require.Equal(t, doc.Epoch, epoch)

	skew := int64(1234)
	p.setClockSkew(skew)
	skewDuration := c.ClockSkew()
	expected := time.Duration(skew) * time.Second
	require.Equal(t, expected, skewDuration)
}

func lenSyncMap(m *sync.Map) int {
	var i int
	m.Range(func(k, v interface{}) bool {
		i++
		return true
	})
	return i
}

func TestPKICachedDoc(t *testing.T) {
	cfg, err := config.LoadFile("testdata/client.toml")
	require.NoError(t, err)

	myMockPKIClient := new(mockPKIClient)
	logbackend, err := log.New("", "debug", false)
	require.NoError(t, err)
	c := &Client{
		logbackend: logbackend,
		cfg:        cfg,
		PKIClient:  myMockPKIClient,
	}
	p := newPKI(c)
	require.Equal(t, 0, lenSyncMap(&p.docs))

	epoch, _, _ := epochtime.Now()

	doc1 := &cpki.Document{
		Epoch: epoch,
	}
	doc2 := &cpki.Document{
		Epoch: epoch + 1,
	}
	doc3 := &cpki.Document{
		Epoch: epoch + 2,
	}
	c.cfg.CachedDocument = doc1

	p = newPKI(c)
	c.pki = p
	require.Equal(t, 1, lenSyncMap(&p.docs))

	p.pruneDocuments(epoch)
	require.Equal(t, 1, lenSyncMap(&p.docs))

	p.pruneDocuments(epoch + 1)
	require.Equal(t, 0, lenSyncMap(&p.docs))

	p = newPKI(c)
	c.pki = p
	require.Equal(t, 1, lenSyncMap(&p.docs))

	myMockPKIClient.doc = doc2
	ctx := context.TODO()
	p.consensusGetter = new(mockConsensusGetter)
	_, doc, err := p.getDocument(ctx, doc2.Epoch)
	require.NoError(t, err)
	require.Equal(t, doc2, doc)

	myMockPKIClient.doc = doc3
	ctx = context.TODO()
	_, doc, err = p.getDocument(ctx, doc3.Epoch)
	require.NoError(t, err)
	require.Equal(t, doc3, doc)
}

func TestPKIGetDocumentConsensusGone(t *testing.T) {
	cfg, err := config.LoadFile("testdata/client.toml")
	require.NoError(t, err)

	logbackend, err := log.New("", "debug", false)
	require.NoError(t, err)
	c := &Client{
		logbackend: logbackend,
		cfg:        cfg,
		PKIClient:  new(mockPKIClient),
	}

	p := newPKI(c)
	p.consensusGetter = &mockConsensusGetter{errorCode: commands.ConsensusGone}

	epoch, _, _ := epochtime.Now()
	ctx := context.TODO()

	_, doc, err := p.getDocument(ctx, epoch)
	require.ErrorIs(t, err, cpki.ErrNoDocument)
	require.Nil(t, doc)
}

func TestPKIGetDocumentConsensusNotFound(t *testing.T) {
	cfg, err := config.LoadFile("testdata/client.toml")
	require.NoError(t, err)

	logbackend, err := log.New("", "debug", false)
	require.NoError(t, err)
	c := &Client{
		logbackend: logbackend,
		cfg:        cfg,
		PKIClient:  new(mockPKIClient),
	}

	p := newPKI(c)
	p.consensusGetter = &mockConsensusGetter{errorCode: commands.ConsensusNotFound}

	epoch, _, _ := epochtime.Now()
	ctx := context.TODO()

	_, doc, err := p.getDocument(ctx, epoch)
	require.ErrorIs(t, err, errConsensusNotFound)
	require.Nil(t, doc)
}

func TestPKIFailedFetchesCachesConsensusGone(t *testing.T) {
	cfg, err := config.LoadFile("testdata/client.toml")
	require.NoError(t, err)

	logbackend, err := log.New("", "debug", false)
	require.NoError(t, err)
	c := &Client{
		logbackend: logbackend,
		cfg:        cfg,
		PKIClient:  new(mockPKIClient),
	}

	p := newPKI(c)
	p.consensusGetter = &mockConsensusGetter{errorCode: commands.ConsensusGone}

	epoch, _, _ := epochtime.Now()

	// Simulate what the worker loop does: fetch, then cache ErrNoDocument.
	err = p.updateDocument(epoch)
	require.ErrorIs(t, err, cpki.ErrNoDocument)

	// Worker caches ErrNoDocument errors.
	p.failedFetches[epoch] = err

	// pruneFailures should keep the entry for the current epoch.
	p.pruneFailures(epoch)
	require.Contains(t, p.failedFetches, epoch)

	// pruneFailures should remove it once the epoch advances.
	p.pruneFailures(epoch + 1)
	require.NotContains(t, p.failedFetches, epoch)
}

func TestPKIFailedFetchesDoesNotCacheConsensusNotFound(t *testing.T) {
	cfg, err := config.LoadFile("testdata/client.toml")
	require.NoError(t, err)

	logbackend, err := log.New("", "debug", false)
	require.NoError(t, err)
	c := &Client{
		logbackend: logbackend,
		cfg:        cfg,
		PKIClient:  new(mockPKIClient),
	}

	p := newPKI(c)
	p.consensusGetter = &mockConsensusGetter{errorCode: commands.ConsensusNotFound}

	epoch, _, _ := epochtime.Now()

	// ConsensusNotFound returns errConsensusNotFound, not ErrNoDocument.
	// The worker loop only caches ErrNoDocument, so this should not be cached.
	err = p.updateDocument(epoch)
	require.ErrorIs(t, err, errConsensusNotFound)

	// Simulate the worker's switch: only ErrNoDocument is cached.
	if err == cpki.ErrNoDocument {
		p.failedFetches[epoch] = err
	}
	require.NotContains(t, p.failedFetches, epoch)
}

func TestPKIRecoveryAfterConsensusGone(t *testing.T) {
	cfg, err := config.LoadFile("testdata/client.toml")
	require.NoError(t, err)

	myMockPKIClient := new(mockPKIClient)
	logbackend, err := log.New("", "debug", false)
	require.NoError(t, err)
	c := &Client{
		logbackend: logbackend,
		cfg:        cfg,
		PKIClient:  myMockPKIClient,
	}

	epoch, _, _ := epochtime.Now()

	// Gateway returns ConsensusGone for current epoch, Ok for next.
	mock := &mockConsensusGetter{
		epochErrors: map[uint64]uint8{
			epoch: commands.ConsensusGone,
		},
	}

	p := newPKI(c)
	p.consensusGetter = mock

	// Current epoch is gone — worker would cache this.
	err = p.updateDocument(epoch)
	require.ErrorIs(t, err, cpki.ErrNoDocument)
	p.failedFetches[epoch] = err

	// Next epoch should succeed (mock returns ConsensusOk by default).
	myMockPKIClient.doc = &cpki.Document{
		Epoch:              epoch + 1,
		SphinxGeometryHash: c.cfg.SphinxGeometry.Hash(),
	}
	err = p.updateDocument(epoch + 1)
	require.NoError(t, err)

	// Verify we have the next epoch's document.
	d := p.GetDocumentByEpoch(epoch + 1)
	require.NotNil(t, d)
	require.Equal(t, epoch+1, d.Epoch)
}

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

type mockConsensusGetter struct{}

func (m *mockConsensusGetter) GetConsensus(ctx context.Context, epoch uint64) (*commands.Consensus, error) {
	return &commands.Consensus{}, nil
}

type mockPKIClient struct {
	doc *cpki.Document
}

func (c *mockPKIClient) Get(ctx context.Context, epoch uint64) (*cpki.Document, []byte, error) {
	return nil, nil, nil // XXX
}

func (c *mockPKIClient) Post(ctx context.Context, epoch uint64, signingPrivateKey sign.PrivateKey, signingPublicKey sign.PublicKey, d *cpki.MixDescriptor, loopstats *loops.LoopStats) error {
	return nil
}

func (c *mockPKIClient) Deserialize(raw []byte) (*cpki.Document, error) {
	return c.doc, nil
}

func TestClientPKIStartStop(t *testing.T) {
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

	doc, err := p.getDocument(ctx, epoch)
	require.NoError(t, err)
	require.NotNil(t, doc)
	require.Equal(t, doc.Epoch, epoch)

	wrongEpoch := uint64(1234567)
	ctx = context.TODO()

	doc, err = p.getDocument(ctx, wrongEpoch)
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
	currentDoc := p.currentDocument()
	require.Nil(t, currentDoc)

	// panic with bad sphinx geometry hash
	err = p.updateDocument(epoch)
	require.NoError(t, err)

	err = p.updateDocument(epoch)
	require.NoError(t, err)

	t.Log("currentDocument works if Sphinx Geometry Hash is correctly set:")
	doc := p.currentDocument()
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

	currentDoc := p.currentDocument()
	require.Nil(t, currentDoc)
	c.WaitForCurrentDocument()
	currentDoc = p.currentDocument()
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

	doc, err := p.getDocument(ctx, epoch)
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
	doc, err := p.getDocument(ctx, doc2.Epoch)
	require.NoError(t, err)
	require.Equal(t, doc2, doc)

	myMockPKIClient.doc = doc3
	ctx = context.TODO()
	doc, err = p.getDocument(ctx, doc3.Epoch)
	require.NoError(t, err)
	require.Equal(t, doc3, doc)
}

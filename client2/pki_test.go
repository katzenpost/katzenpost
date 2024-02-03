package client2

import (
	"context"
	"testing"

	"github.com/katzenpost/katzenpost/client2/config"
	"github.com/katzenpost/katzenpost/core/crypto/rand"
	"github.com/katzenpost/katzenpost/core/crypto/sign"
	"github.com/katzenpost/katzenpost/core/epochtime"
	cpki "github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/wire/commands"
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

func (c *mockPKIClient) Post(ctx context.Context, epoch uint64, signingPrivateKey sign.PrivateKey, signingPublicKey sign.PublicKey, d *cpki.MixDescriptor) error {
	return nil
}

func (c *mockPKIClient) Deserialize(raw []byte) (*cpki.Document, error) {
	return c.doc, nil
}

func TestClientPKIStartStop(t *testing.T) {
	cfg, err := config.LoadFile("testdata/client.toml")
	require.NoError(t, err)

	myMockPKIClient := new(mockPKIClient)
	c := &Client{
		cfg:       cfg,
		PKIClient: myMockPKIClient,
	}

	p := newPKI(c)
	p.consensusGetter = new(mockConsensusGetter)
	p.start()

	p.Halt()
	p.Wait()
}

func TestGetDocument(t *testing.T) {
	cfg, err := config.LoadFile("testdata/client.toml")
	require.NoError(t, err)

	myMockPKIClient := new(mockPKIClient)
	c := &Client{
		cfg:       cfg,
		PKIClient: myMockPKIClient,
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

func TestUpdateDocumentBadSphinxHash(t *testing.T) {
	cfg, err := config.LoadFile("testdata/client.toml")
	require.NoError(t, err)

	myMockPKIClient := new(mockPKIClient)
	c := &Client{
		cfg:       cfg,
		PKIClient: myMockPKIClient,
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

func TestUpdateDocument(t *testing.T) {
	cfg, err := config.LoadFile("testdata/client.toml")
	require.NoError(t, err)

	myMockPKIClient := new(mockPKIClient)
	c := &Client{
		cfg:       cfg,
		PKIClient: myMockPKIClient,
	}

	p := newPKI(c)
	p.consensusGetter = new(mockConsensusGetter)

	epoch, _, _ := epochtime.Now()

	testDoc := &cpki.Document{
		Epoch:              epoch,
		SphinxGeometryHash: c.cfg.SphinxGeometry.Hash(),
	}

	myMockPKIClient.doc = testDoc

	require.Nil(t, p.currentDocument())

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

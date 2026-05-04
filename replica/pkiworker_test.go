package replica

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"

	replicaCommon "github.com/katzenpost/katzenpost/replica/common"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/hash"
	"github.com/katzenpost/hpqc/kem"
	kempem "github.com/katzenpost/hpqc/kem/pem"
	kemschemes "github.com/katzenpost/hpqc/kem/schemes"
	"github.com/katzenpost/hpqc/nike"
	nikeschemes "github.com/katzenpost/hpqc/nike/schemes"
	"github.com/katzenpost/hpqc/rand"
	"github.com/katzenpost/hpqc/sign"
	signschemes "github.com/katzenpost/hpqc/sign/schemes"
	authconfig "github.com/katzenpost/katzenpost/authority/voting/server/config"
	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/pki"
	sConstants "github.com/katzenpost/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/katzenpost/katzenpost/loops"
	"github.com/katzenpost/katzenpost/replica/config"
)

const (
	testDirAuthAddress = "tcp://127.0.0.1:1234"
	testReplicaAddress = "tcp://127.0.0.1:7483"
)

// testSetup holds common test setup data
type testSetup struct {
	pkiScheme     sign.Scheme
	idpubkey      sign.PublicKey
	linkScheme    kem.Scheme
	linkpubkey    kem.PublicKey
	replicaScheme nike.Scheme
	geometry      *geo.Geometry
	cfg           *config.Config
	server        *Server
	idpubkeyblob  []byte
	libpubkeyblob []byte
	id            [32]byte
}

// createTestSetup creates common test setup with keys, config, and server
func createTestSetup(t *testing.T) *testSetup {
	return createTestSetupWithPKIClient(t, nil)
}

func createTestSetupWithPKIClient(t *testing.T, pkiClient pki.Client) *testSetup {
	t.Helper()

	pkiScheme := signschemes.ByName(testPKIScheme)
	idpubkey, _, err := pkiScheme.GenerateKey()
	require.NoError(t, err)

	linkScheme := kemschemes.ByName("Xwing")
	linkpubkey, _, err := linkScheme.GenerateKeyPair()
	require.NoError(t, err)

	replicaScheme := nikeschemes.ByName("x25519")
	nrHops := 5
	payloadSize := 5000
	sphinxScheme := nikeschemes.ByName("x25519")
	geometry := geo.GeometryFromUserForwardPayloadLength(sphinxScheme, payloadSize, true, nrHops)

	cfg := &config.Config{
		PKI: &config.PKI{
			Voting: &config.Voting{
				Authorities: []*authconfig.Authority{
					&authconfig.Authority{
						Identifier:         "dirauth1",
						IdentityPublicKey:  idpubkey,
						PKISignatureScheme: pkiScheme.Name(),
						LinkPublicKey:      linkpubkey,
						WireKEMScheme:      linkScheme.Name(),
						Addresses:          []string{testDirAuthAddress},
					},
				},
			},
		},
		Logging: &config.Logging{
			Disable: false,
			File:    "",
			Level:   "DEBUG",
		},
		DataDir:            filepath.Join(t.TempDir(), "datadir"),
		Identifier:         "replica1",
		WireKEMScheme:      linkScheme.Name(),
		PKISignatureScheme: pkiScheme.Name(),
		ReplicaNIKEScheme:  replicaScheme.Name(),
		SphinxGeometry:     geometry,
		Addresses:          []string{testReplicaAddress},
	}

	var server *Server
	if pkiClient == nil {
		server, err = New(cfg)
	} else {
		server, err = NewWithPKI(cfg, pkiClient)
	}
	require.NoError(t, err)

	idpubkeyblob, err := idpubkey.MarshalBinary()
	require.NoError(t, err)

	libpubkeyblob, err := linkpubkey.MarshalBinary()
	require.NoError(t, err)

	id := hash.Sum256From(idpubkey)

	return &testSetup{
		pkiScheme:     pkiScheme,
		idpubkey:      idpubkey,
		linkScheme:    linkScheme,
		linkpubkey:    linkpubkey,
		replicaScheme: replicaScheme,
		geometry:      geometry,
		cfg:           cfg,
		server:        server,
		idpubkeyblob:  idpubkeyblob,
		libpubkeyblob: libpubkeyblob,
		id:            id,
	}
}

func createManualPKITestSetup(t *testing.T, pkiClient pki.Client) *testSetup {
	t.Helper()

	setup := createTestSetupWithPKIClient(t, pkiClient)
	setup.server.PKIWorker.Halt()

	return setup
}

type mockReplicaPKIClient struct {
	mu          sync.Mutex
	postErr     error
	postEpochs  []uint64
	descriptors []*pki.ReplicaDescriptor
	ctxErrs     []error
}

func (m *mockReplicaPKIClient) GetPKIDocumentForEpoch(ctx context.Context, epoch uint64) (*pki.Document, []byte, error) {
	return nil, nil, pki.ErrNoDocument
}

func (m *mockReplicaPKIClient) Post(ctx context.Context, epoch uint64, signingPrivateKey sign.PrivateKey, signingPublicKey sign.PublicKey, d *pki.MixDescriptor, loopstats *loops.LoopStats) error {
	return nil
}

func (m *mockReplicaPKIClient) PostReplica(ctx context.Context, epoch uint64, signingPrivateKey sign.PrivateKey, signingPublicKey sign.PublicKey, d *pki.ReplicaDescriptor) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.postEpochs = append(m.postEpochs, epoch)
	m.descriptors = append(m.descriptors, d)
	m.ctxErrs = append(m.ctxErrs, ctx.Err())

	return m.postErr
}

func (m *mockReplicaPKIClient) Deserialize(raw []byte) (*pki.Document, error) {
	return pki.ParseDocument(raw)
}

func (m *mockReplicaPKIClient) posts() ([]uint64, []*pki.ReplicaDescriptor) {
	m.mu.Lock()
	defer m.mu.Unlock()

	epochs := append([]uint64(nil), m.postEpochs...)
	descriptors := append([]*pki.ReplicaDescriptor(nil), m.descriptors...)
	return epochs, descriptors
}

func TestReplicaMap(t *testing.T) {
	r := replicaCommon.NewReplicaMap()
	newMap := make(map[[32]byte]*pki.ReplicaDescriptor)
	replica := &pki.ReplicaDescriptor{
		Name: "replica1",
	}

	id := [32]byte{}
	_, err := rand.Reader.Read(id[:])
	require.NoError(t, err)

	newMap[id] = replica
	r.Replace(newMap)

	replica2, ok := r.GetReplicaDescriptor(&id)
	require.True(t, ok)
	require.Equal(t, replica, replica2)
}

func TestAuthenticateCourierConnection(t *testing.T) {
	setup := createTestSetup(t)
	defer setup.server.Shutdown()

	libpubkeypem := kempem.ToPublicPEMString(setup.linkpubkey)

	epoch, _, _ := epochtime.Now()

	advertMap := make(map[string]map[string]interface{})
	advertMap["courier"] = make(map[string]interface{})
	advertMap["courier"]["linkPublicKey"] = libpubkeypem

	kaetzchen := make(map[string]map[string]interface{})
	kaetzchen["courier"] = make(map[string]interface{})

	doc := &pki.Document{
		Epoch: epoch,
		ServiceNodes: []*pki.MixDescriptor{
			&pki.MixDescriptor{
				Name:                    "servicenode1",
				Epoch:                   epoch,
				IdentityKey:             setup.idpubkeyblob,
				LinkKey:                 setup.libpubkeyblob,
				Kaetzchen:               kaetzchen,
				KaetzchenAdvertizedData: advertMap,
			},
		},
	}

	rawDoc, err := doc.MarshalCertificate()
	require.NoError(t, err)

	setup.server.PKIWorker.StoreDocument(epoch, doc, rawDoc)

	// Test that the PKI document is properly stored
	retrievedDoc := setup.server.PKIWorker.documentForEpoch(epoch)
	require.NotNil(t, retrievedDoc)
	require.Equal(t, epoch, retrievedDoc.Epoch)

	// Create and store an updated document with gateway nodes
	updatedDoc := &pki.Document{
		Epoch: epoch,
		GatewayNodes: []*pki.MixDescriptor{
			&pki.MixDescriptor{
				Name:        "servicenode1",
				Epoch:       epoch,
				IdentityKey: setup.idpubkeyblob,
				LinkKey:     setup.libpubkeyblob,
			},
		},
	}

	rawUpdatedDoc, err := updatedDoc.MarshalCertificate()
	require.NoError(t, err)

	setup.server.PKIWorker.StoreDocument(epoch, updatedDoc, rawUpdatedDoc)

	// Test that the document was updated
	retrievedDoc = setup.server.PKIWorker.documentForEpoch(epoch)
	require.NotNil(t, retrievedDoc)
	require.Len(t, retrievedDoc.GatewayNodes, 1)
}

func TestAuthenticateReplicaConnection(t *testing.T) {
	setup := createTestSetup(t)
	defer setup.server.Shutdown()

	ad := make([]byte, sConstants.NodeIDLength)
	copy(ad, setup.id[:])
	epoch, _, _ := epochtime.Now()

	pkiWorker := setup.server.PKIWorker

	// Create and store initial document
	initialDoc := &pki.Document{
		Epoch: epoch,
		ServiceNodes: []*pki.MixDescriptor{
			&pki.MixDescriptor{
				Name:        "servicenode1",
				Epoch:       epoch,
				IdentityKey: setup.idpubkeyblob,
				LinkKey:     setup.libpubkeyblob,
			},
		},
	}

	rawInitialDoc, err := initialDoc.MarshalCertificate()
	require.NoError(t, err)
	pkiWorker.StoreDocument(epoch, initialDoc, rawInitialDoc)

	// Test that no replicas are initially available
	replicas := pkiWorker.ReplicasCopy()
	require.Empty(t, replicas)

	replicaDesc := &pki.ReplicaDescriptor{
		Name:        "replica1",
		Epoch:       epoch,
		IdentityKey: setup.idpubkeyblob,
		LinkKey:     setup.libpubkeyblob,
	}

	// Create and store document with replica
	replicaDoc := &pki.Document{
		Epoch: epoch,
		StorageReplicas: []*pki.ReplicaDescriptor{
			replicaDesc,
		},
	}

	rawReplicaDoc, err := replicaDoc.MarshalCertificate()
	require.NoError(t, err)
	pkiWorker.StoreDocument(epoch, replicaDoc, rawReplicaDoc)
	pkiWorker.replicas.Replace(map[[32]byte]*pki.ReplicaDescriptor{setup.id: replicaDesc})

	// Test that replica is now available
	replicas = pkiWorker.ReplicasCopy()
	require.Len(t, replicas, 1)
	require.Contains(t, replicas, setup.id)
}

func TestDocumentsToFetch(t *testing.T) {
	p := &PKIWorker{
		WorkerBase: pki.NewWorkerBase(nil, nil),
	}

	epochs := p.DocumentsToFetch()
	// The number of epochs to fetch should be between 3 and 4 depending on timing
	// When till < nextFetchTill (near end of epoch), we fetch for next epoch (4 docs)
	// Otherwise, we fetch for current epoch (3 docs)
	require.True(t, len(epochs) >= 3 && len(epochs) <= 4, "Expected 3 or 4 epochs, got %d", len(epochs))

	initialCount := len(epochs)

	// Store a document for the first epoch to simulate it being fetched
	if len(epochs) > 0 {
		doc := &pki.Document{Epoch: epochs[0]}
		rawDoc, err := doc.MarshalCertificate()
		require.NoError(t, err)
		p.StoreDocument(epochs[0], doc, rawDoc)
	}

	epochs2 := p.DocumentsToFetch()
	// After storing one document, we should have one fewer to fetch
	expectedCount2 := initialCount - 1
	require.Equal(t, expectedCount2, len(epochs2))
}

func TestGetFailedFetch(t *testing.T) {
	p := &PKIWorker{
		WorkerBase: pki.NewWorkerBase(nil, nil),
	}

	epochs := p.DocumentsToFetch()
	ok, err := p.GetFailedFetch(epochs[0])
	require.NoError(t, err)
	require.False(t, ok)

	myepoch := epochs[0] - 10
	p.SetFailedFetch(myepoch, errors.New("wtf"))

	ok, err = p.GetFailedFetch(myepoch)
	require.Error(t, err)
	require.True(t, ok)

	p.PruneFailures()

	ok, err = p.GetFailedFetch(myepoch)
	require.NoError(t, err)
	require.False(t, ok)
}

func TestPruneDocuments(t *testing.T) {
	setup := createTestSetup(t)
	defer setup.server.Shutdown()

	ad := make([]byte, sConstants.NodeIDLength)
	copy(ad, setup.id[:])
	now, _, _ := epochtime.Now()
	epoch := now - 10

	pkiWorker := setup.server.PKIWorker

	// Store an old document that should be pruned
	oldDoc := &pki.Document{
		Epoch: epoch,
		ServiceNodes: []*pki.MixDescriptor{
			&pki.MixDescriptor{
				Name:        "servicenode1",
				Epoch:       epoch,
				IdentityKey: setup.idpubkeyblob,
				LinkKey:     setup.libpubkeyblob,
			},
		},
	}

	rawOldDoc, err := oldDoc.MarshalCertificate()
	require.NoError(t, err)
	pkiWorker.StoreDocument(epoch, oldDoc, rawOldDoc)

	pkiWorker.PruneDocuments()

	// Verify the old document was pruned
	retrievedDoc := pkiWorker.documentForEpoch(epoch)
	require.Nil(t, retrievedDoc)
}

func TestAuthenticationDuringEpochTransition(t *testing.T) {
	setup := createTestSetup(t)
	defer setup.server.Shutdown()

	libpubkeypem := kempem.ToPublicPEMString(setup.linkpubkey)

	epoch, _, _ := epochtime.Now()

	advertMap := make(map[string]map[string]interface{})
	advertMap["courier"] = make(map[string]interface{})
	advertMap["courier"]["linkPublicKey"] = libpubkeypem

	kaetzchen := make(map[string]map[string]interface{})
	kaetzchen["courier"] = make(map[string]interface{})

	currentDoc := &pki.Document{
		Epoch: epoch,
		ServiceNodes: []*pki.MixDescriptor{
			&pki.MixDescriptor{
				Name:                    "servicenode1",
				Epoch:                   epoch,
				IdentityKey:             setup.idpubkeyblob,
				LinkKey:                 setup.libpubkeyblob,
				Kaetzchen:               kaetzchen,
				KaetzchenAdvertizedData: advertMap,
			},
		},
	}

	nextDoc := &pki.Document{
		Epoch: epoch + 1,
		ServiceNodes: []*pki.MixDescriptor{
			&pki.MixDescriptor{
				Name:                    "servicenode1",
				Epoch:                   epoch + 1,
				IdentityKey:             setup.idpubkeyblob,
				LinkKey:                 setup.libpubkeyblob,
				Kaetzchen:               kaetzchen,
				KaetzchenAdvertizedData: advertMap,
			},
		},
	}

	pkiWorker := setup.server.PKIWorker

	// Store current epoch document
	rawCurrentDoc, err := currentDoc.MarshalCertificate()
	require.NoError(t, err)
	pkiWorker.StoreDocument(epoch, currentDoc, rawCurrentDoc)

	// Test that current epoch document is available
	doc := pkiWorker.documentForEpoch(epoch)
	require.NotNil(t, doc)
	require.Equal(t, epoch, doc.Epoch)

	// Store next epoch document
	rawNextDoc, err := nextDoc.MarshalCertificate()
	require.NoError(t, err)
	pkiWorker.StoreDocument(epoch+1, nextDoc, rawNextDoc)

	// Test that both epoch documents are available
	doc = pkiWorker.documentForEpoch(epoch)
	require.NotNil(t, doc)

	nextDocRetrieved := pkiWorker.documentForEpoch(epoch + 1)
	require.NotNil(t, nextDocRetrieved)

	// Remove current epoch document by storing nil (simulating deletion)
	pkiWorker.StoreDocument(epoch, nil, nil)

	// Test that only next epoch document is available
	doc = pkiWorker.documentForEpoch(epoch)
	require.Nil(t, doc)

	nextDocRetrieved = pkiWorker.documentForEpoch(epoch + 1)
	require.NotNil(t, nextDocRetrieved)
}

func TestReplicaPublishDescriptorUsesNextEpochUploadWindow(t *testing.T) {
	mockClient := &mockReplicaPKIClient{}
	setup := createManualPKITestSetup(t, mockClient)
	defer setup.server.Shutdown()

	pkiWorker := setup.server.PKIWorker

	currentEpoch, _, _ := epochtime.Now()

	err := pkiWorker.publishDescriptorIfNeeded(context.Background())
	require.NoError(t, err)

	epochs, descriptors := mockClient.posts()
	if len(epochs) == 0 {
		require.Empty(t, descriptors)
		require.Equal(t, uint64(0), pkiWorker.lastPublishedEpoch)
		return
	}

	require.Len(t, epochs, 1)
	require.Len(t, descriptors, 1)
	require.Equal(t, epochs[0], descriptors[0].Epoch)
	require.Equal(t, epochs[0], pkiWorker.lastPublishedEpoch)
	require.GreaterOrEqual(t, epochs[0], currentEpoch+1)
}

func TestReplicaPublishDescriptorSkipsAfterSuccessfulPublish(t *testing.T) {
	mockClient := &mockReplicaPKIClient{}
	setup := createManualPKITestSetup(t, mockClient)
	defer setup.server.Shutdown()

	pkiWorker := setup.server.PKIWorker

	currentEpoch, _, _ := epochtime.Now()
	pkiWorker.lastPublishedEpoch = currentEpoch + 1

	err := pkiWorker.publishDescriptorIfNeeded(context.Background())
	require.NoError(t, err)

	epochs, descriptors := mockClient.posts()
	require.Empty(t, epochs)
	require.Empty(t, descriptors)
	require.Equal(t, currentEpoch+1, pkiWorker.lastPublishedEpoch)
}

func TestReplicaPublishDescriptorDoesNotSuppressTransientFailure(t *testing.T) {
	mockClient := &mockReplicaPKIClient{
		postErr: errors.New("temporary transport failure"),
	}
	setup := createManualPKITestSetup(t, mockClient)
	defer setup.server.Shutdown()

	pkiWorker := setup.server.PKIWorker

	currentEpoch, _, _ := epochtime.Now()

	err := pkiWorker.publishDescriptorIfNeeded(context.Background())

	epochs, descriptors := mockClient.posts()
	if len(epochs) == 0 {
		require.NoError(t, err)
		require.Empty(t, descriptors)
		require.Equal(t, uint64(0), pkiWorker.lastPublishedEpoch)
		return
	}

	require.Error(t, err)
	require.Len(t, epochs, 1)
	require.Len(t, descriptors, 1)
	require.Equal(t, epochs[0], descriptors[0].Epoch)
	require.GreaterOrEqual(t, epochs[0], currentEpoch+1)
	require.Equal(t, uint64(0), pkiWorker.lastPublishedEpoch)
}

func TestReplicaPublishDescriptorSuppressesPermanentInvalidEpoch(t *testing.T) {
	mockClient := &mockReplicaPKIClient{
		postErr: pki.ErrInvalidPostEpoch,
	}
	setup := createManualPKITestSetup(t, mockClient)
	defer setup.server.Shutdown()

	pkiWorker := setup.server.PKIWorker

	currentEpoch, _, _ := epochtime.Now()

	err := pkiWorker.publishDescriptorIfNeeded(context.Background())

	epochs, descriptors := mockClient.posts()
	if len(epochs) == 0 {
		require.NoError(t, err)
		require.Empty(t, descriptors)
		require.Equal(t, uint64(0), pkiWorker.lastPublishedEpoch)
		return
	}

	require.ErrorIs(t, err, pki.ErrInvalidPostEpoch)
	require.Len(t, epochs, 1)
	require.Len(t, descriptors, 1)
	require.Equal(t, epochs[0], descriptors[0].Epoch)
	require.GreaterOrEqual(t, epochs[0], currentEpoch+1)
	require.Equal(t, epochs[0], pkiWorker.lastPublishedEpoch)
}

func TestReplicaPublishDescriptorUsesBoundedUploadContext(t *testing.T) {
	mockClient := &mockReplicaPKIClient{}
	setup := createManualPKITestSetup(t, mockClient)
	defer setup.server.Shutdown()

	pkiWorker := setup.server.PKIWorker

	err := pkiWorker.publishDescriptorIfNeeded(context.Background())
	require.NoError(t, err)

	epochs, _ := mockClient.posts()
	if len(epochs) == 0 {
		return
	}

	mockClient.mu.Lock()
	defer mockClient.mu.Unlock()

	require.Len(t, mockClient.ctxErrs, 1)
	require.NoError(t, mockClient.ctxErrs[0])
}

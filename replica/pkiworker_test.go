package replica

import (
	"errors"
	"path/filepath"
	"sync"
	"testing"

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
	"github.com/katzenpost/katzenpost/replica/common"
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

	server, err := New(cfg)
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

func TestReplicaMap(t *testing.T) {
	r := common.NewReplicaMap()
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
	setup.server.PKIWorker.lock.Lock()

	advertMap := make(map[string]map[string]interface{})
	advertMap["courier"] = make(map[string]interface{})
	advertMap["courier"]["linkPublicKey"] = libpubkeypem

	kaetzchen := make(map[string]map[string]interface{})
	kaetzchen["courier"] = make(map[string]interface{})

	setup.server.PKIWorker.docs[epoch] = &pki.Document{
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
	setup.server.PKIWorker.lock.Unlock()

	// Test that the PKI document is properly stored
	doc := setup.server.PKIWorker.documentForEpoch(epoch)
	require.NotNil(t, doc)
	require.Equal(t, epoch, doc.Epoch)

	setup.server.PKIWorker.lock.Lock()
	setup.server.PKIWorker.docs[epoch] = &pki.Document{
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
	setup.server.PKIWorker.lock.Unlock()

	// Test that the document was updated
	doc = setup.server.PKIWorker.documentForEpoch(epoch)
	require.NotNil(t, doc)
	require.Len(t, doc.GatewayNodes, 1)
}

func TestAuthenticateReplicaConnection(t *testing.T) {
	setup := createTestSetup(t)
	defer setup.server.Shutdown()

	ad := make([]byte, sConstants.NodeIDLength)
	copy(ad, setup.id[:])

	epoch, _, _ := epochtime.Now()
	pkiWorker := setup.server.PKIWorker
	pkiWorker.lock.Lock()
	pkiWorker.docs[epoch] = &pki.Document{
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

	pkiWorker.lock.Unlock()

	// Test that no replicas are initially available
	replicas := pkiWorker.ReplicasCopy()
	require.Empty(t, replicas)

	replicaDesc := &pki.ReplicaDescriptor{
		Name:        "replica1",
		Epoch:       epoch,
		IdentityKey: setup.idpubkeyblob,
		LinkKey:     setup.libpubkeyblob,
	}

	pkiWorker.lock.Lock()
	pkiWorker.docs[epoch] = &pki.Document{
		Epoch: epoch,
		StorageReplicas: []*pki.ReplicaDescriptor{
			replicaDesc,
		},
	}
	pkiWorker.lock.Unlock()
	pkiWorker.replicas.Replace(map[[32]byte]*pki.ReplicaDescriptor{setup.id: replicaDesc})

	// Test that replica is now available
	replicas = pkiWorker.ReplicasCopy()
	require.Len(t, replicas, 1)
	require.Contains(t, replicas, setup.id)
}

func TestDocumentsToFetch(t *testing.T) {
	p := &PKIWorker{
		lock: new(sync.RWMutex),
		docs: make(map[uint64]*pki.Document),
	}
	epochs := p.documentsToFetch()
	_, _, till := epochtime.Now()
	if till < nextFetchTill {
		require.Equal(t, 4, len(epochs))
	} else {
		require.Equal(t, 3, len(epochs))
	}

	p.lock.Lock()
	p.docs[epochs[0]] = nil
	p.lock.Unlock()

	epochs2 := p.documentsToFetch()
	_, _, till = epochtime.Now()
	if till < nextFetchTill {
		require.Equal(t, 3, len(epochs2))
	} else {
		require.Equal(t, 2, len(epochs2))
	}

}

func TestGetFailedFetch(t *testing.T) {
	p := &PKIWorker{
		lock:          new(sync.RWMutex),
		failedFetches: make(map[uint64]error),
	}
	epochs := p.documentsToFetch()
	ok, err := p.getFailedFetch(epochs[0])
	require.NoError(t, err)
	require.False(t, ok)

	myepoch := epochs[0] - 10
	p.setFailedFetch(myepoch, errors.New("wtf"))

	ok, err = p.getFailedFetch(myepoch)
	require.Error(t, err)
	require.True(t, ok)

	p.pruneFailures()

	ok, err = p.getFailedFetch(myepoch)
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
	pkiWorker.lock.Lock()
	pkiWorker.docs[epoch] = &pki.Document{
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
	pkiWorker.lock.Unlock()

	pkiWorker.pruneDocuments()

	pkiWorker.lock.Lock()
	require.Zero(t, len(pkiWorker.docs))
	pkiWorker.lock.Unlock()
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
	pkiWorker.lock.Lock()
	pkiWorker.docs[epoch] = currentDoc
	pkiWorker.lock.Unlock()

	// Test that current epoch document is available
	doc := pkiWorker.documentForEpoch(epoch)
	require.NotNil(t, doc)
	require.Equal(t, epoch, doc.Epoch)

	pkiWorker.lock.Lock()
	pkiWorker.docs[epoch+1] = nextDoc
	pkiWorker.lock.Unlock()

	// Test that both epoch documents are available
	doc = pkiWorker.documentForEpoch(epoch)
	require.NotNil(t, doc)
	nextDocRetrieved := pkiWorker.documentForEpoch(epoch + 1)
	require.NotNil(t, nextDocRetrieved)

	pkiWorker.lock.Lock()
	delete(pkiWorker.docs, epoch)
	pkiWorker.lock.Unlock()

	// Test that only next epoch document is available
	doc = pkiWorker.documentForEpoch(epoch)
	require.Nil(t, doc)
	nextDocRetrieved = pkiWorker.documentForEpoch(epoch + 1)
	require.NotNil(t, nextDocRetrieved)
}

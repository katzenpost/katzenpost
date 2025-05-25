package replica

import (
	"errors"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/hash"
	kempem "github.com/katzenpost/hpqc/kem/pem"
	kemschemes "github.com/katzenpost/hpqc/kem/schemes"
	nikeschemes "github.com/katzenpost/hpqc/nike/schemes"
	"github.com/katzenpost/hpqc/rand"
	signschemes "github.com/katzenpost/hpqc/sign/schemes"

	authconfig "github.com/katzenpost/katzenpost/authority/voting/server/config"
	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/pki"
	sConstants "github.com/katzenpost/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/katzenpost/katzenpost/core/wire"
	"github.com/katzenpost/katzenpost/replica/common"
	"github.com/katzenpost/katzenpost/replica/config"
)

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
	pkiScheme := signschemes.ByName("Ed25519 Sphincs+")
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
						Addresses:          []string{"tcp://127.0.0.1:1234"},
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
		Addresses:          []string{"tcp://127.0.0.1:7483"},
	}
	s, err := New(cfg)
	require.NoError(t, err)

	idpubkeyblob, err := idpubkey.MarshalBinary()
	require.NoError(t, err)

	libpubkeypem := kempem.ToPublicPEMString(linkpubkey)

	libpubkeyblob, err := linkpubkey.MarshalBinary()
	require.NoError(t, err)

	creds := &wire.PeerCredentials{
		AdditionalData: []byte{},
		PublicKey:      linkpubkey,
	}

	epoch, _, _ := epochtime.Now()
	s.pkiWorker.lock.Lock()

	advertMap := make(map[string]map[string]interface{})
	advertMap["courier"] = make(map[string]interface{})
	advertMap["courier"]["linkPublicKey"] = libpubkeypem

	kaetzchen := make(map[string]map[string]interface{})
	kaetzchen["courier"] = make(map[string]interface{})

	s.pkiWorker.docs[epoch] = &pki.Document{
		Epoch: epoch,
		ServiceNodes: []*pki.MixDescriptor{
			&pki.MixDescriptor{
				Name:                    "servicenode1",
				Epoch:                   epoch,
				IdentityKey:             idpubkeyblob,
				LinkKey:                 libpubkeyblob,
				Kaetzchen:               kaetzchen,
				KaetzchenAdvertizedData: advertMap,
			},
		},
	}
	s.pkiWorker.lock.Unlock()

	ok := s.pkiWorker.AuthenticateCourierConnection(creds)
	require.True(t, ok)

	s.pkiWorker.lock.Lock()
	s.pkiWorker.docs[epoch] = &pki.Document{
		Epoch: epoch,
		GatewayNodes: []*pki.MixDescriptor{
			&pki.MixDescriptor{
				Name:        "servicenode1",
				Epoch:       epoch,
				IdentityKey: idpubkeyblob,
				LinkKey:     libpubkeyblob,
			},
		},
	}
	s.pkiWorker.lock.Unlock()

	ok = s.pkiWorker.AuthenticateCourierConnection(creds)
	require.False(t, ok)

	s.Shutdown()
}

func TestAuthenticateReplicaConnection(t *testing.T) {
	pkiScheme := signschemes.ByName("Ed25519 Sphincs+")
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
						Addresses:          []string{"tcp://127.0.0.1:1234"},
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
		Addresses:          []string{"tcp://127.0.0.1:7483"},
	}
	s, err := New(cfg)
	require.NoError(t, err)

	ad := make([]byte, sConstants.NodeIDLength)
	idpubkeyblob, err := idpubkey.MarshalBinary()
	require.NoError(t, err)

	libpubkeyblob, err := linkpubkey.MarshalBinary()
	require.NoError(t, err)

	id := hash.Sum256From(idpubkey)
	copy(ad, id[:])

	creds := &wire.PeerCredentials{
		AdditionalData: ad,
		PublicKey:      linkpubkey,
	}

	epoch, _, _ := epochtime.Now()
	s.pkiWorker.lock.Lock()
	s.pkiWorker.docs[epoch] = &pki.Document{
		Epoch: epoch,
		ServiceNodes: []*pki.MixDescriptor{
			&pki.MixDescriptor{
				Name:        "servicenode1",
				Epoch:       epoch,
				IdentityKey: idpubkeyblob,
				LinkKey:     libpubkeyblob,
			},
		},
	}

	s.pkiWorker.lock.Unlock()

	_, ok := s.pkiWorker.AuthenticateReplicaConnection(creds)
	require.False(t, ok)

	replicaDesc := &pki.ReplicaDescriptor{
		Name:        "replica1",
		Epoch:       epoch,
		IdentityKey: idpubkeyblob,
		LinkKey:     libpubkeyblob,
	}

	s.pkiWorker.lock.Lock()
	s.pkiWorker.docs[epoch] = &pki.Document{
		Epoch: epoch,
		StorageReplicas: []*pki.ReplicaDescriptor{
			replicaDesc,
		},
	}
	s.pkiWorker.lock.Unlock()
	s.pkiWorker.replicas.Replace(map[[32]byte]*pki.ReplicaDescriptor{id: replicaDesc})

	_, ok = s.pkiWorker.AuthenticateReplicaConnection(creds)
	require.True(t, ok)

	s.Shutdown()
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
	pkiScheme := signschemes.ByName("Ed25519 Sphincs+")
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
						Addresses:          []string{"tcp://127.0.0.1:1234"},
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
		Addresses:          []string{"tcp://127.0.0.1:7483"},
	}
	s, err := New(cfg)
	require.NoError(t, err)

	ad := make([]byte, sConstants.NodeIDLength)
	idpubkeyblob, err := idpubkey.MarshalBinary()
	require.NoError(t, err)

	libpubkeyblob, err := linkpubkey.MarshalBinary()
	require.NoError(t, err)

	id := hash.Sum256From(idpubkey)
	copy(ad, id[:])

	now, _, _ := epochtime.Now()
	epoch := now - 10
	s.pkiWorker.lock.Lock()
	s.pkiWorker.docs[epoch] = &pki.Document{
		Epoch: epoch,
		ServiceNodes: []*pki.MixDescriptor{
			&pki.MixDescriptor{
				Name:        "servicenode1",
				Epoch:       epoch,
				IdentityKey: idpubkeyblob,
				LinkKey:     libpubkeyblob,
			},
		},
	}
	s.pkiWorker.lock.Unlock()

	s.pkiWorker.pruneDocuments()

	s.pkiWorker.lock.Lock()
	require.Zero(t, len(s.pkiWorker.docs))
	s.pkiWorker.lock.Unlock()

	s.Shutdown()
}

func TestAuthenticationDuringEpochTransition(t *testing.T) {
	pkiScheme := signschemes.ByName("Ed25519 Sphincs+")
	idpubkey, _, err := pkiScheme.GenerateKey()
	require.NoError(t, err)

	linkScheme := kemschemes.ByName("Xwing")
	linkpubkey, _, err := linkScheme.GenerateKeyPair()
	require.NoError(t, err)

	replicaScheme := nikeschemes.ByName("x25519")
	geometry := geo.GeometryFromUserForwardPayloadLength(nikeschemes.ByName("x25519"), 5000, true, 5)

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
						Addresses:          []string{"tcp://127.0.0.1:1234"},
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
		Addresses:          []string{"tcp://127.0.0.1:7483"},
	}
	s, err := New(cfg)
	require.NoError(t, err)

	libpubkeypem := kempem.ToPublicPEMString(linkpubkey)
	creds := &wire.PeerCredentials{
		AdditionalData: []byte{},
		PublicKey:      linkpubkey,
	}

	epoch, _, _ := epochtime.Now()
	advertMap := make(map[string]map[string]interface{})
	advertMap["courier"] = make(map[string]interface{})
	advertMap["courier"]["linkPublicKey"] = libpubkeypem

	kaetzchen := make(map[string]map[string]interface{})
	kaetzchen["courier"] = make(map[string]interface{})

	idpubkeyblob, err := idpubkey.MarshalBinary()
	require.NoError(t, err)
	libpubkeyblob, err := linkpubkey.MarshalBinary()
	require.NoError(t, err)

	currentDoc := &pki.Document{
		Epoch: epoch,
		ServiceNodes: []*pki.MixDescriptor{
			&pki.MixDescriptor{
				Name:                    "servicenode1",
				Epoch:                   epoch,
				IdentityKey:             idpubkeyblob,
				LinkKey:                 libpubkeyblob,
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
				IdentityKey:             idpubkeyblob,
				LinkKey:                 libpubkeyblob,
				Kaetzchen:               kaetzchen,
				KaetzchenAdvertizedData: advertMap,
			},
		},
	}

	s.pkiWorker.lock.Lock()
	s.pkiWorker.docs[epoch] = currentDoc
	s.pkiWorker.lock.Unlock()

	ok := s.pkiWorker.AuthenticateCourierConnection(creds)
	require.True(t, ok, "Authentication should succeed with current epoch doc")

	s.pkiWorker.lock.Lock()
	s.pkiWorker.docs[epoch+1] = nextDoc
	s.pkiWorker.lock.Unlock()

	ok = s.pkiWorker.AuthenticateCourierConnection(creds)
	require.True(t, ok, "Authentication should succeed with both epoch docs")

	s.pkiWorker.lock.Lock()
	delete(s.pkiWorker.docs, epoch)
	s.pkiWorker.lock.Unlock()

	ok = s.pkiWorker.AuthenticateCourierConnection(creds)
	require.True(t, ok, "Authentication should succeed with next epoch doc")

	s.Shutdown()
}

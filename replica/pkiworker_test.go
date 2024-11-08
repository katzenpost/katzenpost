package replica

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/hash"
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
	"github.com/katzenpost/katzenpost/replica/config"
)

func TestReplicaMap(t *testing.T) {
	r := newReplicaMap()
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

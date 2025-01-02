// SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package replica

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	kemschemes "github.com/katzenpost/hpqc/kem/schemes"
	nikeschemes "github.com/katzenpost/hpqc/nike/schemes"
	ecdh "github.com/katzenpost/hpqc/nike/x25519"
	"github.com/katzenpost/hpqc/rand"
	signschemes "github.com/katzenpost/hpqc/sign/schemes"

	authconfig "github.com/katzenpost/katzenpost/authority/voting/server/config"
	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/katzenpost/katzenpost/core/wire/commands"
	"github.com/katzenpost/katzenpost/replica/common"
	"github.com/katzenpost/katzenpost/replica/config"
)

func TestInitDataDir(t *testing.T) {
	s := &Server{
		cfg: &config.Config{
			DataDir: t.TempDir(),
		},
	}
	err := s.initDataDir()
	require.Error(t, err)

	s.cfg.DataDir = filepath.Join(t.TempDir(), "datadir")
	err = s.initDataDir()
	require.NoError(t, err)

	err = s.initDataDir()
	require.NoError(t, err)
}

func TestNew(t *testing.T) {
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
		Addresses:          []string{"tcp://127.0.0.1:2413"},
	}
	s, err := New(cfg)
	require.NoError(t, err)

	s.Shutdown()

	s, err = New(cfg)
	require.NoError(t, err)

	s.Shutdown()
}

func TestGetRemoteShards(t *testing.T) {
	dname, err := os.MkdirTemp("", fmt.Sprintf("replica.testState %d", os.Getpid()))
	require.NoError(t, err)
	defer os.RemoveAll(dname)

	nike := ecdh.Scheme(rand.Reader)
	forwardPayloadLength := 1234
	nrHops := 5
	geo := geo.GeometryFromUserForwardPayloadLength(nike, forwardPayloadLength, true, nrHops)
	require.NotNil(t, geo)

	pkiScheme := signschemes.ByName("ed25519")
	linkScheme := kemschemes.ByName("x25519")
	replicaScheme := nikeschemes.ByName("x25519")

	pk, _, err := pkiScheme.GenerateKey()
	require.NoError(t, err)

	cfg := &config.Config{
		PKI:        &config.PKI{},
		Identifier: "replica1",
		Logging: &config.Logging{
			Disable: false,
			File:    "",
			Level:   "DEBUG",
		},
		DataDir:            dname,
		SphinxGeometry:     geo,
		PKISignatureScheme: pkiScheme.Name(),
		ReplicaNIKEScheme:  replicaScheme.Name(),
		WireKEMScheme:      linkScheme.Name(),
		Addresses:          []string{"tcp://127.0.0.1:34394"},
	}

	s := &Server{
		identityPublicKey: pk,
		cfg:               cfg,
		pkiWorker: &PKIWorker{
			replicas:      common.NewReplicaMap(),
			lock:          new(sync.RWMutex),
			docs:          make(map[uint64]*pki.Document),
			rawDocs:       make(map[uint64][]byte),
			failedFetches: make(map[uint64]error),
		},
	}
	s.pkiWorker.server = s
	s.connector = new(mockConnector)

	epoch, _, _ := epochtime.Now()

	numReplicas := 10
	replicas := make([]*pki.ReplicaDescriptor, 0, numReplicas)

	for i := 0; i < numReplicas; i++ {
		replica := generateReplica(t, pkiScheme, linkScheme, replicaScheme)
		replicas = append(replicas, replica)
	}

	doc := &pki.Document{
		Epoch:           epoch,
		StorageReplicas: replicas,
	}
	s.pkiWorker.lock.Lock()
	s.pkiWorker.replicas = common.NewReplicaMap()
	s.pkiWorker.docs[epoch] = doc
	s.pkiWorker.lock.Unlock()

	s.pkiWorker.server = s
	s.pkiWorker.log = s.LogBackend().GetLogger("pki")

	err = s.initLogging()
	require.NoError(t, err)

	st := &state{
		server: s,
		log:    s.LogBackend().GetLogger("state"),
	}
	s.state = st
	st.initDB()

	cmds := commands.NewStorageReplicaCommands(geo, replicaScheme)
	require.NotNil(t, cmds)

	numShares := 4
	boxIDs := make([]*[32]byte, numShares)
	for i := 0; i < numShares; i++ {
		replicaWriteCmd1 := &commands.ReplicaWrite{
			Cmds:      cmds,
			BoxID:     &[32]byte{},
			Signature: &[32]byte{},
			Payload:   []byte("hello i am a payload"),
		}
		_, err = rand.Reader.Read(replicaWriteCmd1.BoxID[:])
		require.NoError(t, err)

		_, err = rand.Reader.Read(replicaWriteCmd1.Signature[:])
		require.NoError(t, err)

		err = st.handleReplicaWrite(replicaWriteCmd1)
		require.NoError(t, err)

		boxIDs[i] = replicaWriteCmd1.BoxID
	}

	boxid := &[32]byte{}
	_, err = rand.Reader.Read(boxid[:])
	require.NoError(t, err)

	shards, err := common.GetRemoteShards(s.identityPublicKey, boxid, doc)
	require.NoError(t, err)

	t.Logf("SHARDS: %v", shards)

	myreplicas := s.pkiWorker.replicas.Copy()
	require.Zero(t, len(myreplicas))

	s.pkiWorker.updateReplicas(doc)

	myreplicas = s.pkiWorker.replicas.Copy()
	require.Equal(t, numReplicas, len(myreplicas))
}

// SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package replica

import (
	"path/filepath"
	"testing"

	replicaCommon "github.com/katzenpost/katzenpost/replica/common"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/bacap"
	kemschemes "github.com/katzenpost/hpqc/kem/schemes"
	nikeschemes "github.com/katzenpost/hpqc/nike/schemes"
	"github.com/katzenpost/hpqc/rand"
	signschemes "github.com/katzenpost/hpqc/sign/schemes"

	authconfig "github.com/katzenpost/katzenpost/authority/voting/server/config"
	"github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/katzenpost/katzenpost/core/wire/commands"
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
	// Setup test environment
	schemes := NewTestSchemes()
	geometry := CreateTestGeometryCustom(schemes, 1234, 5)
	tempDir := CreateTestTempDir(t, "replica_test_state")
	keys := GenerateTestKeys(t, schemes)

	cfg := &config.Config{
		PKI:        &config.PKI{},
		Identifier: "replica1",
		Logging: &config.Logging{
			Disable: false,
			File:    "",
			Level:   "DEBUG",
		},
		DataDir:            tempDir,
		SphinxGeometry:     geometry,
		PKISignatureScheme: schemes.PKI.Name(),
		ReplicaNIKEScheme:  schemes.Replica.Name(),
		WireKEMScheme:      schemes.Link.Name(),
		Addresses:          []string{"tcp://127.0.0.1:34394"},
	}

	// Create PKI worker with proper structure
	pkiWorker := &PKIWorker{
		replicas:   replicaCommon.NewReplicaMap(),
		WorkerBase: pki.NewWorkerBase(nil, nil),
	}

	s := &Server{
		identityPublicKey: keys.IdentityPubKey,
		cfg:               cfg,
		PKIWorker:         pkiWorker,
	}
	s.PKIWorker.server = s
	s.connector = newMockConnector(s)

	numReplicas := 10
	replicas := make([]*pki.ReplicaDescriptor, 0, numReplicas)

	for i := 0; i < numReplicas; i++ {
		replica := GenerateTestReplica(t, schemes, i)
		replicas = append(replicas, replica)
	}

	doc := CreateTestPKIDocument(t, replicas, nil)
	StoreTestDocument(t, s.PKIWorker, doc)
	s.PKIWorker.replicas = replicaCommon.NewReplicaMap()

	s.PKIWorker.server = s

	err := s.initLogging()
	require.NoError(t, err)

	st := newState(s)
	s.state = st
	st.initDB()

	cmds := commands.NewStorageReplicaCommands(geometry, schemes.Replica)
	require.NotNil(t, cmds)

	numShares := 4
	boxIDs := make([]*[bacap.BoxIDSize]byte, numShares)
	for i := 0; i < numShares; i++ {
		replicaWriteCmd1 := &commands.ReplicaWrite{
			Cmds:      cmds,
			BoxID:     &[bacap.BoxIDSize]byte{},
			Signature: &[bacap.SignatureSize]byte{},
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

	boxid := &[bacap.BoxIDSize]byte{}
	_, err = rand.Reader.Read(boxid[:])
	require.NoError(t, err)

	shards, err := replicaCommon.GetRemoteShards(s.identityPublicKey, boxid, doc)
	require.NoError(t, err)

	t.Logf("SHARDS: %v", shards)

	myreplicas := s.PKIWorker.replicas.Copy()
	require.Zero(t, len(myreplicas))

	s.PKIWorker.updateReplicas(doc)

	myreplicas = s.PKIWorker.replicas.Copy()
	require.Equal(t, numReplicas, len(myreplicas))
}

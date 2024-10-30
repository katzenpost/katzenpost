// SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package replica

import (
	"os"
	"sync"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/kem"
	kemschemes "github.com/katzenpost/hpqc/kem/schemes"
	"github.com/katzenpost/hpqc/nike"
	nikeschemes "github.com/katzenpost/hpqc/nike/schemes"
	ecdh "github.com/katzenpost/hpqc/nike/x25519"
	"github.com/katzenpost/hpqc/rand"
	"github.com/katzenpost/hpqc/sign"
	signschemes "github.com/katzenpost/hpqc/sign/schemes"

	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/katzenpost/katzenpost/core/wire/commands"
	"github.com/katzenpost/katzenpost/replica/config"
)

func generateReplica(t *testing.T, pkiScheme sign.Scheme, linkScheme kem.Scheme, replicaScheme nike.Scheme) *pki.ReplicaDescriptor {
	idkey := make([]byte, pkiScheme.PublicKeySize())
	_, err := rand.Reader.Read(idkey)
	require.NoError(t, err)

	linkkey := make([]byte, linkScheme.PublicKeySize())
	_, err = rand.Reader.Read(linkkey)
	require.NoError(t, err)

	replicakey := make([]byte, replicaScheme.PublicKeySize())
	_, err = rand.Reader.Read(replicakey)
	require.NoError(t, err)

	envelopeKeys := make(map[uint64][]byte)
	epoch, _, _ := epochtime.Now()
	envelopeKeys[epoch] = make([]byte, 32)

	return &pki.ReplicaDescriptor{
		Name:         "fake replica name",
		IdentityKey:  idkey,
		LinkKey:      linkkey,
		EnvelopeKeys: make(map[uint64][]byte),
		Addresses:    map[string][]string{"tcp": []string{"tcp://127.0.0.1:12345"}},
	}
}

type mockConnector struct{}

func (m *mockConnector) ForceUpdate() {}

func (m *mockConnector) DispatchCommand(cmd commands.Command, idHash *[32]byte) {}

func TestState(t *testing.T) {
	dname, err := os.MkdirTemp("", "replca.testState")
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
		DataDir:        dname,
		SphinxGeometry: geo,
		Logging: &config.Logging{
			Disable: false,
			File:    "",
			Level:   "DEBUG",
		},
	}

	s := &Server{
		identityPublicKey: pk,
		cfg:               cfg,
		pkiWorker: &PKIWorker{
			replicas:      newReplicaMap(),
			lock:          new(sync.RWMutex),
			docs:          make(map[uint64]*pki.Document),
			rawDocs:       make(map[uint64][]byte),
			failedFetches: make(map[uint64]error),
		},
	}

	s.connector = new(mockConnector)

	epoch, _, _ := epochtime.Now()

	numReplicas := 10
	replicas := make([]*pki.ReplicaDescriptor, 0, numReplicas)

	for i := 0; i < numReplicas; i++ {
		replica := generateReplica(t, pkiScheme, linkScheme, replicaScheme)
		replicas = append(replicas, replica)
	}

	s.pkiWorker.lock.Lock()
	s.pkiWorker.docs[epoch] = &pki.Document{
		Epoch:           epoch,
		StorageReplicas: replicas,
	}
	s.pkiWorker.lock.Unlock()

	err = s.initLogging()
	require.NoError(t, err)

	s.pkiWorker.server = s
	s.pkiWorker.log = s.LogBackend().GetLogger("pki")

	st := &state{
		server: s,
		log:    s.LogBackend().GetLogger("state"),
	}

	st.initDB()

	cmds := commands.NewStorageReplicaCommands(geo)
	require.NotNil(t, cmds)

	numShares := 40
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

	replicaReadCmd := &commands.ReplicaRead{
		Cmds:  cmds,
		BoxID: &[32]byte{},
	}
	copy(replicaReadCmd.BoxID[:], boxIDs[0][:])

	_, err = st.handleReplicaRead(replicaReadCmd)
	require.NoError(t, err)

	t.Log("BEFORE Rebalance")
	st.Rebalance()
	t.Log("AFTER Rebalance")
}

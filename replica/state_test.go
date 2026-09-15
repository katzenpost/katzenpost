// SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package replica

import (
	"bytes"
	"os"
	"testing"

	replicaCommon "github.com/katzenpost/katzenpost/replica/common"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/bacap"
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
	"github.com/katzenpost/katzenpost/pigeonhole"
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
		ReplicaID:    0,
		IdentityKey:  idkey,
		LinkKey:      linkkey,
		EnvelopeKeys: make(map[uint64][]byte),
		Addresses:    map[string][]string{"tcp": {"tcp://127.0.0.1:12345"}},
	}
}

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
		ReplicaNIKEScheme: "X25519",
		DataDir:           dname,
		SphinxGeometry:    geo,
		Logging: &config.Logging{
			Disable: false,
			File:    "",
			Level:   "DEBUG",
		},
	}
	cfg.SetDefaultTimeouts()

	pkiWorker := &PKIWorker{
		replicas:   replicaCommon.NewReplicaMap(),
		WorkerBase: pki.NewWorkerBase(nil, nil),
	}

	s := &Server{
		identityPublicKey: pk,
		cfg:               cfg,
		PKIWorker:         pkiWorker,
		proxySema:         make(chan struct{}, cfg.ProxyWorkerCount),
	}

	s.connector = new(mockConnector)

	epoch, _, _ := epochtime.Now()

	numReplicas := 10
	replicas := make([]*pki.ReplicaDescriptor, 0, numReplicas)

	for i := 0; i < numReplicas; i++ {
		replica := generateReplica(t, pkiScheme, linkScheme, replicaScheme)
		replicas = append(replicas, replica)
	}

	// Store the document
	doc := &pki.Document{
		Epoch:           epoch,
		StorageReplicas: replicas,
	}
	rawDoc, err := doc.MarshalCertificate()
	require.NoError(t, err)
	pkiWorker.StoreDocument(epoch, doc, rawDoc)

	err = s.initLogging()
	require.NoError(t, err)

	pkiWorker.server = s

	st := &state{
		server: s,
		log:    s.LogBackend().GetLogger("state"),
	}

	st.initDB()

	cmds := commands.NewStorageReplicaCommands(geo, replicaScheme)
	require.NotNil(t, cmds)

	payload := []byte("hello i am a payload")
	signature := &[bacap.SignatureSize]byte{}
	boxid := &[bacap.BoxIDSize]byte{}
	_, err = rand.Reader.Read(signature[:])
	require.NoError(t, err)
	_, err = rand.Reader.Read(boxid[:])
	require.NoError(t, err)

	numShares := 2
	boxIDs := make([]*[32]byte, numShares)
	for i := 0; i < numShares; i++ {
		replicaWriteCmd1 := &commands.ReplicaWrite{
			Cmds:      cmds,
			BoxID:     boxid,
			Signature: signature,
			Payload:   payload,
		}
		_, err = rand.Reader.Read(replicaWriteCmd1.BoxID[:])
		require.NoError(t, err)

		_, err = rand.Reader.Read(replicaWriteCmd1.Signature[:])
		require.NoError(t, err)

		err = st.handleReplicaWrite(replicaWriteCmd1)
		require.NoError(t, err)

		boxIDs[i] = replicaWriteCmd1.BoxID
	}

	replicaReadCmd := &pigeonhole.ReplicaRead{}
	copy(replicaReadCmd.BoxID[:], boxIDs[0][:])

	box, err := st.stateHandleReplicaRead(replicaReadCmd)
	require.NoError(t, err)

	require.Equal(t, box.BoxID[:], boxid[:])
	require.Equal(t, box.Payload, payload)
	require.Equal(t, box.Signature[:], signature[:])

	t.Log("BEFORE Rebalance")
	st.Rebalance("test")
	t.Log("AFTER Rebalance")
}

func TestStateClosedDatabaseGuards(t *testing.T) {
	dataDir, err := os.MkdirTemp("", "replica-closed-guards-*")
	require.NoError(t, err)
	defer os.RemoveAll(dataDir)

	st := newTestState(t, dataDir)
	st.initDB()
	st.Close()

	var boxID [32]byte
	var sig [64]byte

	_, err = st.stateHandleReplicaRead(&pigeonhole.ReplicaRead{BoxID: boxID})
	require.ErrorIs(t, err, ErrDBClosed)

	err = st.handleReplicaWrite(&commands.ReplicaWrite{BoxID: &boxID, Signature: &sig, Payload: []byte("x")})
	require.ErrorContains(t, err, errDatabaseClosed)

	err = st.handleReplicaTombstone(boxID, sig)
	require.ErrorContains(t, err, errDatabaseClosed)

	err = st.WipeStaleBoxes()
	require.ErrorContains(t, err, errDatabaseClosed)

	err = st.Rebalance("test")
	require.ErrorContains(t, err, errDatabaseClosed)

	_, _, err = st.loadLastRebalanceFingerprint()
	require.ErrorContains(t, err, errDatabaseClosed)

	require.ErrorContains(t, st.storeLastRebalanceFingerprint([32]byte{}), errDatabaseClosed)
}

func TestStateReadCorruptedValue(t *testing.T) {
	dataDir, err := os.MkdirTemp("", "replica-corrupt-read-*")
	require.NoError(t, err)
	defer os.RemoveAll(dataDir)

	st := newTestState(t, dataDir)
	st.initDB()
	defer st.Close()

	var boxID [32]byte
	boxID[0] = 0x42
	require.NoError(t, st.db.Set(boxKey(currentReplicaEpoch(), boxID[:]), []byte("not a serialized box"), nil))

	_, err = st.stateHandleReplicaRead(&pigeonhole.ReplicaRead{BoxID: boxID})
	require.ErrorIs(t, err, ErrFailedToDeserialize)
}

func TestHandleReplicaWriteRejectsWhenStorageFull(t *testing.T) {
	dataDir, err := os.MkdirTemp("", "replica-storage-full-*")
	require.NoError(t, err)
	defer os.RemoveAll(dataDir)

	st := newTestState(t, dataDir)
	st.initDB()
	defer st.Close()

	st.storageFull.Store(true)
	var boxID [32]byte
	var sig [64]byte
	err = st.handleReplicaWrite(&commands.ReplicaWrite{BoxID: &boxID, Signature: &sig, Payload: []byte("payload")})
	require.ErrorIs(t, err, ErrStorageFull)
}

func TestRebalanceSkipsMalformedKey(t *testing.T) {
	dataDir, err := os.MkdirTemp("", "replica-rebalance-malformed-*")
	require.NoError(t, err)
	defer os.RemoveAll(dataDir)

	st := newTestState(t, dataDir)
	st.initDB()
	defer st.Close()

	// A key shorter than a BoxID prefix must be skipped, not crash the
	// rebalance scan. With no valid boxes and no cached PKI document the
	// scan has nothing else to do, so success proves the skip path.
	require.NoError(t, st.db.Set(epochPrefix(currentReplicaEpoch()), []byte("x"), nil))
	require.NoError(t, st.Rebalance("test"))
}

func TestDBOnDiskBytes(t *testing.T) {
	dataDir, err := os.MkdirTemp("", "replica-disk-bytes-*")
	require.NoError(t, err)
	defer os.RemoveAll(dataDir)

	st := newTestState(t, dataDir)
	st.initDB()

	n, ok := st.dbOnDiskBytes()
	require.True(t, ok)
	require.Greater(t, n, uint64(0), "an open database must report disk usage")

	st.Close()
	n, ok = st.dbOnDiskBytes()
	require.False(t, ok)
	require.Zero(t, n)
}

func TestRefreshStorageFullQuota(t *testing.T) {
	dataDir, err := os.MkdirTemp("", "replica-storage-quota-*")
	require.NoError(t, err)
	defer os.RemoveAll(dataDir)

	st := newTestState(t, dataDir)
	st.initDB()
	defer st.Close()

	require.False(t, st.storageFull.Load())

	st.server.cfg.MaxStorageMiB = 1
	// Write well over the 1 MiB quota so the disk-usage branch trips.
	big := bytes.Repeat([]byte{0xAB}, 2<<20)
	require.NoError(t, st.db.Set(boxKey(currentReplicaEpoch(), make([]byte, 32)), big, nil))

	st.refreshStorageFull()
	require.True(t, st.storageFull.Load(), "exceeding MaxStorageMiB must mark the replica full")
}

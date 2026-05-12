// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package replica

import (
	"os"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/bacap"
	kemschemes "github.com/katzenpost/hpqc/kem/schemes"
	nikeschemes "github.com/katzenpost/hpqc/nike/schemes"
	ecdh "github.com/katzenpost/hpqc/nike/x25519"
	"github.com/katzenpost/hpqc/rand"
	signschemes "github.com/katzenpost/hpqc/sign/schemes"

	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/katzenpost/katzenpost/core/wire/commands"
	"github.com/katzenpost/katzenpost/replica/common"
	"github.com/katzenpost/katzenpost/replica/config"
)

// countingConnector wraps mockConnector and tallies DispatchCommand
// invocations so tests can verify whether Rebalance actually ran.
type countingConnector struct {
	mockConnector
	dispatched atomic.Int64
}

func (c *countingConnector) DispatchCommand(cmd commands.Command, idHash *[32]byte) {
	c.dispatched.Add(1)
}

func TestReplicaSetFingerprintCanonical(t *testing.T) {
	pkiScheme := signschemes.ByName("ed25519")

	keysA := make([][]byte, 4)
	for i := range keysA {
		pub, _, err := pkiScheme.GenerateKey()
		require.NoError(t, err)
		blob, err := pub.MarshalBinary()
		require.NoError(t, err)
		keysA[i] = blob
	}

	descs := func(blobs [][]byte) []*pki.ReplicaDescriptor {
		out := make([]*pki.ReplicaDescriptor, len(blobs))
		for i, b := range blobs {
			out[i] = &pki.ReplicaDescriptor{IdentityKey: b}
		}
		return out
	}

	ordered := &pki.Document{StorageReplicas: descs(keysA)}
	reversed := &pki.Document{StorageReplicas: descs([][]byte{keysA[3], keysA[2], keysA[1], keysA[0]})}
	require.Equal(t, replicaSetFingerprint(ordered), replicaSetFingerprint(reversed),
		"fingerprint must be invariant under StorageReplicas reordering")

	// A different membership must produce a different fingerprint.
	extraPub, _, err := pkiScheme.GenerateKey()
	require.NoError(t, err)
	extraBlob, err := extraPub.MarshalBinary()
	require.NoError(t, err)
	withExtra := &pki.Document{StorageReplicas: descs(append(append([][]byte(nil), keysA...), extraBlob))}
	require.NotEqual(t, replicaSetFingerprint(ordered), replicaSetFingerprint(withExtra),
		"fingerprint must change when membership changes")

	// Documents with no replicas yield the empty-input digest, and nil is
	// treated identically.
	require.Equal(t, replicaSetFingerprint(nil), replicaSetFingerprint(&pki.Document{}))
}

func TestLastRebalanceFingerprintRoundtrip(t *testing.T) {
	st, cleanup := newMarkerTestState(t)
	defer cleanup()

	_, ok, err := st.loadLastRebalanceFingerprint()
	require.NoError(t, err)
	require.False(t, ok, "fresh database must report no persisted fingerprint")

	var fp [32]byte
	_, err = rand.Reader.Read(fp[:])
	require.NoError(t, err)
	require.NoError(t, st.storeLastRebalanceFingerprint(fp))

	got, ok, err := st.loadLastRebalanceFingerprint()
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, fp, got)

	// Survives a close-and-reopen of the underlying state.
	dataDir := st.server.cfg.DataDir
	st.Close()

	st2 := &state{server: st.server, log: st.log}
	st2.initDB()
	defer st2.Close()

	got2, ok, err := st2.loadLastRebalanceFingerprint()
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, fp, got2)

	// Sanity-check the path is what we expected.
	require.Equal(t, dataDir, st.server.cfg.DataDir)
}

func TestMaybeStartupRebalanceSkipsWhenFingerprintMatches(t *testing.T) {
	srv, _, cc, _, cleanup := newRebalanceServer(t)
	defer cleanup()

	doc := srv.PKIWorker.LastCachedPKIDocument()
	require.NotNil(t, doc)
	require.NoError(t, srv.state.storeLastRebalanceFingerprint(replicaSetFingerprint(doc)))

	srv.maybeStartupRebalance()
	require.Zero(t, cc.dispatched.Load(),
		"matching fingerprint should suppress the startup rebalance entirely")
}

func TestMaybeStartupRebalanceRunsWhenFingerprintDiffers(t *testing.T) {
	srv, boxCount, cc, _, cleanup := newRebalanceServer(t)
	defer cleanup()

	require.Greater(t, boxCount, 0, "test must have seeded at least one box")
	require.NoError(t, srv.state.storeLastRebalanceFingerprint([32]byte{0xAA}))

	srv.maybeStartupRebalance()
	require.EqualValues(t, boxCount, cc.dispatched.Load(),
		"differing fingerprint should provoke a full rebalance dispatching every kept box")

	doc := srv.PKIWorker.LastCachedPKIDocument()
	require.NotNil(t, doc)
	fp, ok, err := srv.state.loadLastRebalanceFingerprint()
	require.NoError(t, err)
	require.True(t, ok)
	require.Equal(t, replicaSetFingerprint(doc), fp,
		"successful rebalance must persist the current PKI fingerprint")
}

// newMarkerTestState constructs a minimal state with backing storage,
// just enough to exercise the metadata column family. It does not seed
// any boxes or PKI documents.
func newMarkerTestState(t *testing.T) (*state, func()) {
	dataDir, err := os.MkdirTemp("", "replica-marker-test-*")
	require.NoError(t, err)

	nikeScheme := ecdh.Scheme(rand.Reader)
	geom := geo.GeometryFromUserForwardPayloadLength(nikeScheme, 1234, true, 5)

	pkiScheme := signschemes.ByName("ed25519")
	pk, _, err := pkiScheme.GenerateKey()
	require.NoError(t, err)

	cfg := &config.Config{
		ReplicaNIKEScheme: "X25519",
		DataDir:           dataDir,
		SphinxGeometry:    geom,
		Logging: &config.Logging{
			Disable: false,
			File:    "",
			Level:   "DEBUG",
		},
	}
	cfg.SetDefaultTimeouts()

	pkiWorker := &PKIWorker{
		replicas:   common.NewReplicaMap(),
		WorkerBase: pki.NewWorkerBase(nil, nil),
	}
	s := &Server{
		identityPublicKey: pk,
		cfg:               cfg,
		PKIWorker:         pkiWorker,
		proxySema:         make(chan struct{}, cfg.ProxyWorkerCount),
	}
	require.NoError(t, s.initLogging())
	pkiWorker.server = s
	s.connector = new(mockConnector)

	st := &state{server: s, log: s.LogBackend().GetLogger("state")}
	st.initDB()
	s.state = st

	cleanup := func() {
		st.Close()
		os.RemoveAll(dataDir)
	}
	return st, cleanup
}

// newRebalanceServer constructs a server whose state holds a handful of
// boxes addressed to a two-replica shard set in which we are one of
// the two. With K=2 and two replicas, every box's remote shard set is
// exactly the other replica, so a full Rebalance dispatches one command
// per stored box; that count is the witness our startup-gate tests use.
func newRebalanceServer(t *testing.T) (srv *Server, boxCount int, cc *countingConnector, dataDir string, cleanup func()) {
	dataDir, err := os.MkdirTemp("", "replica-rebalance-test-*")
	require.NoError(t, err)

	nikeScheme := ecdh.Scheme(rand.Reader)
	geom := geo.GeometryFromUserForwardPayloadLength(nikeScheme, 1234, true, 5)
	pkiScheme := signschemes.ByName("ed25519")
	linkScheme := kemschemes.ByName("x25519")
	replicaScheme := nikeschemes.ByName("x25519")

	ourPub, _, err := pkiScheme.GenerateKey()
	require.NoError(t, err)
	ourBlob, err := ourPub.MarshalBinary()
	require.NoError(t, err)

	peerPub, _, err := pkiScheme.GenerateKey()
	require.NoError(t, err)
	peerBlob, err := peerPub.MarshalBinary()
	require.NoError(t, err)

	mkReplica := func(blob []byte, id uint8) *pki.ReplicaDescriptor {
		linkkey := make([]byte, linkScheme.PublicKeySize())
		_, err := rand.Reader.Read(linkkey)
		require.NoError(t, err)
		envkey := make([]byte, replicaScheme.PublicKeySize())
		_, err = rand.Reader.Read(envkey)
		require.NoError(t, err)
		epoch, _, _ := epochtime.Now()
		envMap := map[uint64][]byte{epoch: envkey}
		return &pki.ReplicaDescriptor{
			Name:         "r",
			ReplicaID:    id,
			IdentityKey:  blob,
			LinkKey:      linkkey,
			EnvelopeKeys: envMap,
			Addresses:    map[string][]string{"tcp": {"tcp://127.0.0.1:1"}},
		}
	}

	replicas := []*pki.ReplicaDescriptor{mkReplica(ourBlob, 0), mkReplica(peerBlob, 1)}

	epoch, _, _ := epochtime.Now()
	configuredKeys := [][]byte{append([]byte(nil), ourBlob...), append([]byte(nil), peerBlob...)}
	doc := &pki.Document{
		Epoch:                         epoch,
		StorageReplicas:               replicas,
		ConfiguredReplicaIDs:          []uint8{0, 1},
		ConfiguredReplicaIdentityKeys: configuredKeys,
	}

	cfg := &config.Config{
		ReplicaNIKEScheme: "X25519",
		DataDir:           dataDir,
		SphinxGeometry:    geom,
		Logging: &config.Logging{
			Disable: false,
			File:    "",
			Level:   "DEBUG",
		},
	}
	cfg.SetDefaultTimeouts()

	pkiWorker := &PKIWorker{
		replicas:   common.NewReplicaMap(),
		WorkerBase: pki.NewWorkerBase(nil, nil),
	}
	srv = &Server{
		identityPublicKey: ourPub,
		cfg:               cfg,
		PKIWorker:         pkiWorker,
		proxySema:         make(chan struct{}, cfg.ProxyWorkerCount),
	}
	require.NoError(t, srv.initLogging())
	pkiWorker.server = srv

	rawDoc, err := doc.MarshalCertificate()
	require.NoError(t, err)
	pkiWorker.StoreDocument(epoch, doc, rawDoc)

	cc = &countingConnector{mockConnector: mockConnector{server: srv}}
	srv.connector = cc

	st := &state{server: srv, log: srv.LogBackend().GetLogger("state")}
	st.initDB()
	srv.state = st

	// Seed three boxes via the regular write path so they land in the
	// current replica epoch's bucket and are eligible for Rebalance.
	cmds := commands.NewStorageReplicaCommands(geom, replicaScheme)
	boxCount = 3
	for i := 0; i < boxCount; i++ {
		boxid := &[bacap.BoxIDSize]byte{}
		_, err = rand.Reader.Read(boxid[:])
		require.NoError(t, err)
		signature := &[bacap.SignatureSize]byte{}
		_, err = rand.Reader.Read(signature[:])
		require.NoError(t, err)
		write := &commands.ReplicaWrite{
			Cmds:      cmds,
			BoxID:     boxid,
			Signature: signature,
			Payload:   []byte("payload"),
		}
		require.NoError(t, st.handleReplicaWrite(write))
	}

	cleanup = func() {
		st.Close()
		os.RemoveAll(dataDir)
	}
	return srv, boxCount, cc, dataDir, cleanup
}

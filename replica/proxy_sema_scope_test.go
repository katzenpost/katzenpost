// SPDX-FileCopyrightText: Copyright (C) 2026 Katzenpost Contributors
// SPDX-License-Identifier: AGPL-3.0-only

package replica

import (
	"bytes"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	pgeo "github.com/katzenpost/katzenpost/pigeonhole/geo"
	replicaCommon "github.com/katzenpost/katzenpost/replica/common"

	"github.com/katzenpost/hpqc/kem/mkem"
	kemschemes "github.com/katzenpost/hpqc/kem/schemes"
	"github.com/katzenpost/hpqc/nike"
	nikeschemes "github.com/katzenpost/hpqc/nike/schemes"
	"github.com/katzenpost/hpqc/rand"
	signschemes "github.com/katzenpost/hpqc/sign/schemes"

	"github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/katzenpost/katzenpost/core/wire/commands"
	"github.com/katzenpost/katzenpost/pigeonhole"
	"github.com/katzenpost/katzenpost/replica/config"
)

// semaScopeTestEnv bundles the hand-built server and connection used by the
// head-of-line blocking regression tests. The server's connector is a
// mockConnector whose DispatchCommand never delivers a reply, so any
// proxied request blocks for the full ProxyRequestTimeout.
type semaScopeTestEnv struct {
	server   *Server
	keys     *TestKeys
	cfg      *config.Config
	doc      *pki.Document
	listener *Listener
	inConn   *incomingConn
	dummyOut chan *senderRequest
	emitter  *delayedReplyEmitter
}

// setupSemaScopeTestServer builds a real, self-contained Server by hand:
// envelope keys, state+DB, pigeonhole geometry, a real
// ProxyRequestManager, a one-slot proxy worker pool and a three-replica
// PKI document of which this server is replica 0. No worker goroutine is
// started on the incoming connection: tests drive onReplicaCommand
// directly, exactly like TestIncomingConn.
func setupSemaScopeTestServer(t *testing.T) *semaScopeTestEnv {
	t.Helper()

	pkiScheme := signschemes.ByName(testPKIScheme)
	linkScheme := kemschemes.ByName("Xwing")
	sphinxScheme := nikeschemes.ByName("x25519")
	replicaScheme := replicaCommon.NikeScheme

	schemes := &TestSchemes{PKI: pkiScheme, Link: linkScheme, Replica: replicaScheme, Sphinx: sphinxScheme}
	geometry := geo.GeometryFromUserForwardPayloadLength(sphinxScheme, testDefaultPayload, true, testDefaultNrHops)

	dname := CreateTestTempDir(t, "sema_scope_test")
	cfg := CreateTestConfig(t, schemes, geometry, dname, "replica0", []string{"tcp://127.0.0.1:34394"})
	// A one-slot pool: a single in-flight proxied request saturates it.
	cfg.ProxyWorkerCount = 1
	cfg.ProxyRequestTimeout = 30

	keys := GenerateTestKeys(t, schemes)
	server := CreateTestServer(t, cfg, keys, nil)

	require.NoError(t, server.initDataDir())
	require.NoError(t, server.initLogging())

	pigeonholeGeo, err := pgeo.NewGeometryFromSphinx(geometry, replicaScheme)
	require.NoError(t, err)
	server.pigeonholeGeo = pigeonholeGeo

	replicaEpoch, _, _ := replicaCommon.ReplicaNow()
	server.envelopeKeys, err = NewEnvelopeKeys(replicaScheme, server.logBackend.GetLogger("envelope keys"), dname, replicaEpoch)
	require.NoError(t, err)

	st := &state{server: server, log: server.LogBackend().GetLogger("state")}
	server.state = st
	st.initDB()

	server.proxyManager = NewProxyRequestManager(server.logBackend.GetLogger("proxy manager"), time.Duration(cfg.ProxyRequestTimeout)*time.Second)

	// PKI document listing this server (replica 0) plus two holder
	// replicas, so K=2 shards of a box always resolve to real
	// descriptors with per-epoch envelope keys.
	keypair, err := server.envelopeKeys.GetKeypair(replicaEpoch)
	require.NoError(t, err)
	myIDKey, err := server.identityPublicKey.MarshalBinary()
	require.NoError(t, err)

	serverDesc := &pki.ReplicaDescriptor{
		Name:        "replica0",
		ReplicaID:   0,
		IdentityKey: myIDKey,
		LinkKey:     keys.LinkKeyBlob,
		Addresses:   map[string][]string{"tcp": {"tcp://127.0.0.1:34394"}},
		EnvelopeKeys: map[uint64][]byte{
			replicaEpoch: keypair.PublicKey.Bytes(),
		},
	}
	doc := CreateTestPKIDocument(t, []*pki.ReplicaDescriptor{
		serverDesc,
		semaScopeHolderDescriptor(t, schemes, 1),
		semaScopeHolderDescriptor(t, schemes, 2),
	}, nil)
	StoreTestDocument(t, server.PKIWorker, doc)

	// Listener plus an incomingConn with a mock session; the worker is
	// never started, so commands are processed by calling
	// onReplicaCommand directly.
	connRx, _ := net.Pipe()
	listener, err := newListener(server, 0, "tcp://127.0.0.1:0")
	require.NoError(t, err)
	inConn := newIncomingConn(listener, connRx, server.cfg.SphinxGeometry, linkScheme, pkiScheme)
	inConn.setSession(&MockSession{pk: keys.LinkPubKey, ad: make([]byte, 32)})

	dummyOut := make(chan *senderRequest, 16)
	emitter := newDelayedReplyEmitter(dummyOut, server.logBackend, "test", func() time.Duration { return fallbackReplyJitter })

	env := &semaScopeTestEnv{
		server:   server,
		keys:     keys,
		cfg:      cfg,
		doc:      doc,
		listener: listener,
		inConn:   inConn,
		dummyOut: dummyOut,
		emitter:  emitter,
	}

	t.Cleanup(func() {
		// Halt the listener first: it closes closeAllCh, which unblocks
		// the still-pending proxy round-trip (sendProxyRequestSync
		// selects on closeAllCh) and makes the handler goroutine skip
		// emitting its late reply. Only then may the emitter be halted.
		listener.Halt()
		emitter.Halt()
		server.proxyManager.Shutdown()
	})
	return env
}

// semaScopeHolderDescriptor builds a storage-replica descriptor with a fresh
// identity and a current-epoch envelope key, so proxyToShard can
// encapsulate to it (the mock connector never delivers a reply).
func semaScopeHolderDescriptor(t *testing.T, schemes *TestSchemes, index int) *pki.ReplicaDescriptor {
	t.Helper()
	keys := GenerateTestKeys(t, schemes)
	replicaEpoch, _, _ := replicaCommon.ReplicaNow()
	return &pki.ReplicaDescriptor{
		Name:        fmt.Sprintf("replica%d", index),
		ReplicaID:   uint8(index),
		IdentityKey: keys.IdentityKeyBlob,
		LinkKey:     keys.LinkKeyBlob,
		Addresses:   map[string][]string{"tcp": {fmt.Sprintf("tcp://127.0.0.1:%d", 19100+index)}},
		EnvelopeKeys: map[uint64][]byte{
			replicaEpoch: keys.ReplicaKeyBlob,
		},
	}
}

// findBoxByShardMembership returns a box ID whose K=2 shards either
// include this server (wantLocal) or exclude it (wantProxy).
func findBoxByShardMembership(t *testing.T, server *Server, doc *pki.Document, wantLocal bool) [32]byte {
	t.Helper()
	myIDKey, err := server.identityPublicKey.MarshalBinary()
	require.NoError(t, err)
	for i := 0; i < 500; i++ {
		var boxID [32]byte
		_, err := rand.Reader.Read(boxID[:])
		require.NoError(t, err)
		shards, err := replicaCommon.GetShards(&boxID, doc)
		require.NoError(t, err)
		require.NotEmpty(t, shards)
		isLocal := false
		for _, shard := range shards {
			if bytes.Equal(shard.IdentityKey, myIDKey) {
				isLocal = true
				break
			}
		}
		if isLocal == wantLocal {
			return boxID
		}
	}
	t.Fatalf("could not find a box whose shards %s this server", map[bool]string{true: "include", false: "exclude"}[wantLocal])
	return [32]byte{}
}

// semaScopeValidReplicaMessage builds a genuine ReplicaMessage: a read for the
// given box, MKEM-encapsulated to this server's current-epoch envelope
// key, so handleReplicaMessage can decrypt and reach the shard logic.
func semaScopeValidReplicaMessage(t *testing.T, server *Server, boxID [32]byte) *commands.ReplicaMessage {
	t.Helper()
	innerMsg := &pigeonhole.ReplicaInnerMessage{
		MessageType: 0, // 0 = read
		ReadMsg:     &pigeonhole.ReplicaRead{BoxID: boxID},
	}
	padded, err := pigeonhole.PadInnerMessageForEncryption(innerMsg, server.pigeonholeGeo)
	require.NoError(t, err)
	replicaEpoch, _, _ := replicaCommon.ReplicaNow()
	keypair, err := server.envelopeKeys.GetKeypair(replicaEpoch)
	require.NoError(t, err)
	_, ct := replicaCommon.MKEMNikeScheme.Encapsulate([]nike.PublicKey{keypair.PublicKey}, padded)
	return &commands.ReplicaMessage{
		Cmds:               commands.NewStorageReplicaCommands(server.cfg.SphinxGeometry, replicaCommon.NikeScheme),
		PigeonholeGeometry: server.pigeonholeGeo,
		Scheme:             replicaCommon.NikeScheme,
		SenderEPubKey:      ct.EphemeralPublicKey.Bytes(),
		DEK:                (*[mkem.DEKSize]byte)(ct.DEKCiphertexts[0]),
		Ciphertext:         ct.Envelope,
	}
}

// TestReplicaMessageNotBlockedBySaturatedProxyPool is the minimal
// regression test for the head-of-line blocking fix: handling a
// ReplicaMessage that needs no proxying must not wait on the proxy
// worker pool. With the pool saturated (its only slot occupied), the
// error reply from decrypting a garbage ReplicaMessage must still be
// emitted promptly.
func TestReplicaMessageNotBlockedBySaturatedProxyPool(t *testing.T) {
	env := setupSemaScopeTestServer(t)

	// Occupy the only proxy worker slot, simulating an in-flight proxied
	// request holding the pool hostage.
	env.server.proxySema <- struct{}{}
	defer func() { <-env.server.proxySema }()

	senderEPubKey := make([]byte, commands.HybridKeySize(replicaCommon.NikeScheme))
	_, err := rand.Reader.Read(senderEPubKey)
	require.NoError(t, err)
	dek := &[mkem.DEKSize]byte{}
	_, err = rand.Reader.Read(dek[:])
	require.NoError(t, err)
	ciphertext := make([]byte, 1000)
	_, err = rand.Reader.Read(ciphertext)
	require.NoError(t, err)

	// Garbage crypto: handleReplicaMessage fails at MKEM decapsulation
	// and returns an error reply before consulting the PKI document, the
	// state or the proxy machinery.
	replicaMessage := &commands.ReplicaMessage{
		Cmds:               commands.NewStorageReplicaCommands(env.cfg.SphinxGeometry, replicaCommon.NikeScheme),
		PigeonholeGeometry: env.server.pigeonholeGeo,
		Scheme:             replicaCommon.NikeScheme,
		SenderEPubKey:      senderEPubKey,
		DEK:                dek,
		Ciphertext:         ciphertext,
	}

	replyCommand, ok := env.inConn.onReplicaCommand(replicaMessage, env.emitter)
	require.True(t, ok)
	require.Nil(t, replyCommand)

	select {
	case req := <-env.dummyOut:
		require.NotNil(t, req.ReplicaMessageReply, "expected a ReplicaMessageReply to be emitted")
		require.NotEqual(t, uint8(0), req.ReplicaMessageReply.ErrorCode, "garbage crypto should yield an error reply")
	case <-time.After(5 * time.Second):
		t.Fatal("ReplicaMessage handling was blocked behind a saturated proxy worker pool")
	}
}

// TestProxySaturationDoesNotBlockLocalRead drives a real proxied request
// through the shard logic so that it genuinely pins the only proxy worker
// slot, then proves a local (shard) read completes without waiting on the
// pool. On the pre-fix code the local read's handler goroutine blocks on
// the same full semaphore and no reply is emitted.
func TestProxySaturationDoesNotBlockLocalRead(t *testing.T) {
	env := setupSemaScopeTestServer(t)

	// boxA: not sharded to this server -> proxied to a shard holder,
	// which never replies through the mock connector, so the request
	// blocks for ProxyRequestTimeout holding the sole proxy slot.
	boxA := findBoxByShardMembership(t, env.server, env.doc, false)
	// boxB: sharded to this server -> served locally.
	boxB := findBoxByShardMembership(t, env.server, env.doc, true)

	proxyMsg := semaScopeValidReplicaMessage(t, env.server, boxA)
	localMsg := semaScopeValidReplicaMessage(t, env.server, boxB)

	// Phase 1: launch the proxied read; it must acquire and hold the only
	// proxy worker slot.
	_, ok := env.inConn.onReplicaCommand(proxyMsg, env.emitter)
	require.True(t, ok)

	require.Eventually(t, func() bool { return len(env.server.proxySema) == 1 },
		10*time.Second, 20*time.Millisecond,
		"proxied request did not acquire the proxy worker slot")

	// Phase 2: a local read for a box this server shards must be served
	// without waiting on the saturated proxy pool.
	_, ok = env.inConn.onReplicaCommand(localMsg, env.emitter)
	require.True(t, ok)

	select {
	case req := <-env.dummyOut:
		require.NotNil(t, req.ReplicaMessageReply, "expected a ReplicaMessageReply to be emitted")
	case <-time.After(5 * time.Second):
		t.Fatal("local read was blocked behind a saturated proxy worker pool")
	}
}

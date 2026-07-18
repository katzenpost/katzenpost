// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package replica

import (
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/bacap"
	kemSchemes "github.com/katzenpost/hpqc/kem/schemes"
	"github.com/katzenpost/hpqc/nike"
	nikeSchemes "github.com/katzenpost/hpqc/nike/schemes"
	signSchemes "github.com/katzenpost/hpqc/sign/schemes"

	"github.com/katzenpost/katzenpost/client/constants"
	"github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/katzenpost/katzenpost/pigeonhole"
	pigeonholeGeo "github.com/katzenpost/katzenpost/pigeonhole/geo"
	"github.com/katzenpost/katzenpost/replica"
	replicaCommon "github.com/katzenpost/katzenpost/replica/common"
	"github.com/katzenpost/katzenpost/replica/config"
)

// faultProxy is a test-owned TCP interposer that sits between the courier
// and one replica. In forward mode it copies bytes both ways transparently;
// in sever mode it refuses new connections and closes every live one, which
// tears down the courier's wire session to the replica exactly as a network
// partition would. It exists because no existing suite kills a courier<->replica
// session and asserts that the courier recovers on its own.
type faultProxy struct {
	ln     net.Listener
	target string
	sever  atomic.Bool

	mu    sync.Mutex
	conns map[net.Conn]struct{}
}

func newFaultProxy(t *testing.T, listenAddr, targetAddr string) *faultProxy {
	ln, err := net.Listen("tcp", listenAddr)
	require.NoError(t, err)
	fp := &faultProxy{
		ln:     ln,
		target: targetAddr,
		conns:  make(map[net.Conn]struct{}),
	}
	go fp.acceptLoop()
	return fp
}

func (fp *faultProxy) acceptLoop() {
	for {
		client, err := fp.ln.Accept()
		if err != nil {
			return // listener closed
		}
		if fp.sever.Load() {
			client.Close()
			continue
		}
		go fp.handle(client)
	}
}

func (fp *faultProxy) handle(client net.Conn) {
	upstream, err := net.Dial("tcp", fp.target)
	if err != nil {
		client.Close()
		return
	}
	fp.track(client)
	fp.track(upstream)
	defer func() {
		client.Close()
		upstream.Close()
		fp.untrack(client)
		fp.untrack(upstream)
	}()

	done := make(chan struct{}, 2)
	go func() { io.Copy(upstream, client); done <- struct{}{} }()
	go func() { io.Copy(client, upstream); done <- struct{}{} }()
	<-done
}

func (fp *faultProxy) track(c net.Conn) {
	fp.mu.Lock()
	fp.conns[c] = struct{}{}
	fp.mu.Unlock()
}

func (fp *faultProxy) untrack(c net.Conn) {
	fp.mu.Lock()
	delete(fp.conns, c)
	fp.mu.Unlock()
}

// setSever flips the partition state. Severing also drops every live
// connection so an established session dies immediately, not just future dials.
func (fp *faultProxy) setSever(on bool) {
	fp.sever.Store(on)
	if on {
		fp.closeAllConns()
	}
}

func (fp *faultProxy) closeAllConns() {
	fp.mu.Lock()
	defer fp.mu.Unlock()
	for c := range fp.conns {
		c.Close()
	}
}

func (fp *faultProxy) Close() {
	fp.ln.Close()
	fp.closeAllConns()
}

// partitionEnv bundles a standard test environment with the proxies
// interposed on each courier->replica link.
type partitionEnv struct {
	env     *testEnvironment
	proxies []*faultProxy
}

func (p *partitionEnv) severAll(on bool) {
	for _, fp := range p.proxies {
		fp.setSever(on)
	}
}

// setupPartitionTestEnvironment mirrors setupTestEnvironmentWithReplicas but
// advertises a per-replica proxy port in each descriptor while the replica
// keeps listening on its real port, so the courier dials through the proxies.
// The courier's WriteTimeout is set low so a stalled send fails fast. Existing
// tests are untouched; this deliberately does not modify the shared helper.
func setupPartitionTestEnvironment(t *testing.T, numReplicas int) *partitionEnv {
	tempDir, err := os.MkdirTemp("", "courier_replica_partition_*")
	require.NoError(t, err)

	portBase := 19000 + (int(time.Now().UnixNano()) % 1000)
	proxyBase := portBase + 1000

	sphinxGeo := geo.GeometryFromUserForwardPayloadLength(nikeSchemes.ByName("X25519"), 5000, true, 5)
	pkiScheme := signSchemes.ByName(testPKIScheme)
	linkScheme := kemSchemes.ByName("Xwing")

	courierDir := filepath.Join(tempDir, "courier")
	require.NoError(t, os.MkdirAll(courierDir, 0700))
	courierCfg := createCourierConfig(t, courierDir, pkiScheme, linkScheme, sphinxGeo)
	courierCfg.WriteTimeout = 2000 // 2s fault-detection bound (default is 1min)

	_, courierLinkPubKey := generateCourierLinkKeys(t, courierDir, courierCfg.WireKEMScheme)
	serviceDesc := makeServiceDescriptor(t, courierLinkPubKey)

	replicaDescriptors := make([]*pki.ReplicaDescriptor, numReplicas)
	replicaConfigs := make([]*config.Config, numReplicas)
	replicaKeys := make([]map[uint64]nike.PublicKey, numReplicas)
	proxies := make([]*faultProxy, numReplicas)

	for i := 0; i < numReplicas; i++ {
		// Proxy listens on proxyBase+i, forwards to the replica's real port.
		proxies[i] = newFaultProxy(t,
			fmt.Sprintf("127.0.0.1:%d", proxyBase+i),
			fmt.Sprintf("127.0.0.1:%d", portBase+i))

		replicaDir := filepath.Join(tempDir, fmt.Sprintf(testReplicaNameFormat, i))
		require.NoError(t, os.MkdirAll(replicaDir, 0700))
		replicaConfigs[i] = createReplicaConfig(t, replicaDir, pkiScheme, linkScheme, i, sphinxGeo, portBase)
		myReplicaKeys, linkPubKey, replicaIdentityPubKey := generateReplicaKeys(t, replicaDir, replicaConfigs[i].PKISignatureScheme, replicaConfigs[i].WireKEMScheme)
		replicaDescriptors[i] = makeReplicaDescriptor(t, i, linkPubKey, replicaIdentityPubKey, myReplicaKeys, portBase)
		// Advertise the proxy port so the courier dials through the shim.
		replicaDescriptors[i].Addresses["tcp"] = []string{fmt.Sprintf("tcp://127.0.0.1:%d", proxyBase+i)}
		replicaKeys[i] = myReplicaKeys
	}

	sharedMockPKIClient := createMockPKIClient(t, sphinxGeo, serviceDesc, replicaDescriptors)

	replicas := make([]*replica.Server, numReplicas)
	for i := 0; i < numReplicas; i++ {
		replicas[i] = createReplicaServer(t, replicaConfigs[i], sharedMockPKIClient)
	}
	courier := createCourierServer(t, courierCfg, sharedMockPKIClient)

	for i, r := range replicas {
		require.NoError(t, r.PKIWorker.ForceFetchPKI(), "replica %d PKI fetch", i)
		r.ForceConnectorUpdate()
	}
	require.NoError(t, courier.PKI.ForceFetchPKI())
	courier.ForceConnectorUpdate()

	pigeonholeGeometry, err := pigeonholeGeo.NewGeometryFromSphinx(sphinxGeo, replicaCommon.NikeScheme)
	require.NoError(t, err)

	router := newResponseRouter()
	courier.Courier.SetWriteFunc(router.writeFunc)

	cleanup := func() {
		for _, r := range replicas {
			if r != nil {
				r.Shutdown()
				r.Wait()
			}
		}
		for _, fp := range proxies {
			fp.Close()
		}
		os.RemoveAll(tempDir)
	}

	env := &testEnvironment{
		tempDir:        tempDir,
		replicas:       replicas,
		courier:        courier,
		mockPKIClient:  sharedMockPKIClient,
		replicaConfigs: replicaConfigs,
		courierConfig:  courierCfg,
		cleanup:        cleanup,
		replicaKeys:    replicaKeys,
		geometry:       pigeonholeGeometry,
		responseRouter: router,
	}
	return &partitionEnv{env: env, proxies: proxies}
}

// decryptReadReply unwraps a courier read reply back to the box plaintext,
// following the same MKEM + BACAP sequence as testBoxRoundTrip. NextBoxID
// peeks without advancing; DecryptNext advances the stateful reader.
func decryptReadReply(t *testing.T, env *testEnvironment, reader *bacap.StatefulReader, readRequest *pigeonhole.CourierEnvelope, reply *pigeonhole.CourierEnvelopeReply, readPrivKey nike.PrivateKey) []byte {
	replicaEpoch, _, _ := replicaCommon.ReplicaNow()
	replicaIndex := int(readRequest.IntermediateReplicas[reply.ReplyIndex])
	replicaPubKey := env.replicaKeys[replicaIndex][replicaEpoch]

	rawInnerMsg, err := mkemNikeScheme.DecryptEnvelope(readPrivKey, replicaPubKey, reply.Payload)
	require.NoError(t, err)
	innerBytes, err := pigeonhole.ExtractMessageFromPaddedPayload(rawInnerMsg)
	require.NoError(t, err)
	innerMsg, err := pigeonhole.ParseReplicaMessageReplyInnerMessage(innerBytes)
	require.NoError(t, err)
	require.NotNil(t, innerMsg.ReadReply)

	boxID, err := reader.NextBoxID()
	require.NoError(t, err)
	var signature [64]byte
	copy(signature[:], innerMsg.ReadReply.Signature[:])
	paddedPlaintext, err := reader.DecryptNext(constants.PIGEONHOLE_CTX, *boxID, innerMsg.ReadReply.Payload, signature)
	require.NoError(t, err)
	plaintext, err := pigeonhole.ExtractMessageFromPaddedPayload(paddedPlaintext)
	require.NoError(t, err)
	return plaintext
}

// readAndVerifyBox reads the next box in the reader's sequence and asserts it
// equals expected, falling back to polling if the first read is not yet served.
func readAndVerifyBox(t *testing.T, env *testEnvironment, reader *bacap.StatefulReader, expected []byte) {
	readRequest, readPrivKey := composeReadRequest(t, env, reader)
	reply := injectCourierEnvelope(t, env, readRequest)
	if len(reply.Payload) == 0 {
		reply = waitForReplicaResponse(t, env, readRequest)
	}
	require.Greater(t, len(reply.Payload), 0, "read reply payload must not be empty")
	require.Equal(t, expected, decryptReadReply(t, env, reader, readRequest, reply, readPrivKey))
}

// TestCourierReplicaPartitionRecovery is the regression guard for the courier
// reconnect-wedge deadlock (commit d68e44d6): after the courier<->replica links
// are severed and then healed, the courier must re-establish its sessions on its
// own and a write that was ACKed to the client during the partition must still
// become readable. Before the fix the courier's outgoing worker wedged and the
// only recovery was a process restart, so this test would hang to its timeout.
func TestCourierReplicaPartitionRecovery(t *testing.T) {
	// t.Parallel() is intentionally not called: like the other integration
	// tests here, this drives real servers on fixed ports.
	p := setupPartitionTestEnvironment(t, 3)
	defer p.env.cleanup()

	time.Sleep(2 * time.Second)
	waitForCourierPKI(t, p.env)
	waitForReplicasPKI(t, p.env)

	writer, reader := aliceAndBobKeyExchangeKeys(t, p.env)

	// Baseline through the proxies: write box 0, read it back. Proves the
	// shim is transparent when forwarding.
	baseline := []byte("baseline before partition")
	writeReply := injectCourierEnvelope(t, p.env, aliceComposesNextMessage(t, baseline, p.env, writer))
	require.Equal(t, uint8(0), writeReply.ReplyIndex)
	require.Len(t, writeReply.Payload, 0)
	time.Sleep(5 * time.Second) // propagate to replicas
	readAndVerifyBox(t, p.env, reader, baseline)

	// Partition: sever every courier<->replica link. The courier's sessions
	// die and its outgoing workers must not wedge.
	t.Log("severing all courier<->replica links")
	p.severAll(true)

	// Write box 1 during the partition. The courier ACKs the client (that
	// path is in-process and never crosses the proxy), then its dispatch to
	// the replicas fails on the severed link and is requeued.
	duringPartition := []byte("written during partition")
	writeReply2 := injectCourierEnvelope(t, p.env, aliceComposesNextMessage(t, duringPartition, p.env, writer))
	require.Equal(t, uint8(0), writeReply2.ReplyIndex, "write must be ACKed even mid-partition")
	require.Len(t, writeReply2.Payload, 0)

	// Keep the partition up briefly so the courier observes the session
	// deaths and enters its reconnect loop, then heal.
	time.Sleep(5 * time.Second)
	t.Log("healing all courier<->replica links")
	p.severAll(false)

	// Recovery: the box written during the partition must become readable
	// once the courier reconnects on its own and drains the requeued write.
	// waitForReplicaResponse re-polls the read for up to 120s; before the
	// deadlock fix the courier never reconnected and this never completes.
	readRequest, readPrivKey := composeReadRequest(t, p.env, reader)
	reply := injectCourierEnvelope(t, p.env, readRequest)
	if len(reply.Payload) == 0 {
		reply = waitForReplicaResponse(t, p.env, readRequest)
	}
	require.True(t, reply.ReplyIndex < 2, "ReplyIndex should be 0 or 1")
	require.Greater(t, len(reply.Payload), 0, "box written during the partition must be served after recovery")

	got := decryptReadReply(t, p.env, reader, readRequest, reply, readPrivKey)
	require.Equal(t, duringPartition, got, "recovered payload must match what was written during the partition")
}

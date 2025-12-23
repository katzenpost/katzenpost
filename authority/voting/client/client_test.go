// client_test.go - Katzenpost voting authority client tests.
// Copyright (C) 2018  David Stainton
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

// Package client implements the Katzenpost voting authority client.
package client

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"
	"gopkg.in/op/go-logging.v1"

	"github.com/katzenpost/hpqc/hash"
	"github.com/katzenpost/hpqc/kem"
	"github.com/katzenpost/hpqc/kem/schemes"
	ecdh "github.com/katzenpost/hpqc/nike/x25519"
	"github.com/katzenpost/hpqc/rand"
	"github.com/katzenpost/hpqc/sign"
	signSchemes "github.com/katzenpost/hpqc/sign/schemes"

	"github.com/katzenpost/katzenpost/authority/voting/server/config"
	"github.com/katzenpost/katzenpost/core/cert"
	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/retry"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/katzenpost/katzenpost/core/wire"
	"github.com/katzenpost/katzenpost/core/wire/commands"
)

var testingSchemeName = "xwing"
var testingScheme = schemes.ByName(testingSchemeName)
var testSignatureScheme = signSchemes.ByName("Ed25519")

type descriptor struct {
	desc *pki.MixDescriptor
	raw  []byte
}

func generateRandomTopology(nodes []*pki.MixDescriptor, layers int) [][]*pki.MixDescriptor {
	rng := rand.NewMath()
	nodeIndexes := rng.Perm(len(nodes))
	topology := make([][]*pki.MixDescriptor, layers)
	for idx, layer := 0, 0; idx < len(nodes); idx++ {
		n := nodes[nodeIndexes[idx]]
		topology[layer] = append(topology[layer], n)
		layer++
		layer = layer % len(topology)
	}
	return topology
}

func generateMixKeys(epoch uint64) (map[uint64][]byte, error) {
	m := make(map[uint64][]byte)
	for i := epoch; i < epoch+3; i++ {
		publickey, _, err := ecdh.Scheme(rand.Reader).GenerateKeyPairFromEntropy(rand.Reader)
		if err != nil {
			return nil, err
		}
		m[uint64(i)] = publickey.Bytes()
	}
	return m, nil
}

func generateNodes(isServiceNode, isGateway bool, num int, epoch uint64) ([]*pki.MixDescriptor, error) {
	mixes := []*pki.MixDescriptor{}

	for i := 0; i < num; i++ {
		mixIdentityPublicKey, _, err := testSignatureScheme.GenerateKey()
		if err != nil {
			return nil, err
		}
		mixKeys, err := generateMixKeys(epoch)
		if err != nil {
			return nil, err
		}
		var name string
		if isGateway {
			name = fmt.Sprintf("NSA_Spy_Satelite_Provider%d", i)
		} else {
			name = fmt.Sprintf("NSA_Spy_Satelite_Mix%d", i)
		}

		scheme := testingScheme
		linkPubKey, _, err := scheme.GenerateKeyPair()
		if err != nil {
			return nil, err
		}

		linkKeyBlob, err := linkPubKey.MarshalBinary()
		if err != nil {
			return nil, err
		}

		blob, err := mixIdentityPublicKey.MarshalBinary()
		if err != nil {
			return nil, err
		}

		mix := &pki.MixDescriptor{
			Name:        name,
			Epoch:       epoch,
			IdentityKey: blob,
			LinkKey:     linkKeyBlob,
			MixKeys:     mixKeys,
			Addresses: map[string][]string{
				"tcp4": []string{fmt.Sprintf("tcp4://127.0.0.1:%d", i+1)},
			},
			Kaetzchen:     nil,
			IsGatewayNode: isGateway,
			IsServiceNode: isServiceNode,
			LoadWeight:    0,
		}
		mixes = append(mixes, mix)
	}
	return mixes, nil
}

func generateMixnet(numMixes, numProviders int, epoch uint64) (*pki.Document, error) {
	mixes, err := generateNodes(false, false, numMixes, epoch)
	if err != nil {
		return nil, err
	}
	serviceNodes, err := generateNodes(true, false, numProviders, epoch)
	if err != nil {
		return nil, err
	}
	gateways, err := generateNodes(false, true, numProviders, epoch)
	if err != nil {
		return nil, err
	}

	gatewayDescriptors := make([]*pki.MixDescriptor, len(gateways))
	for i, p := range gateways {
		gatewayDescriptors[i] = p
	}

	serviceDescriptors := make([]*pki.MixDescriptor, len(serviceNodes))
	for i, p := range serviceNodes {
		serviceDescriptors[i] = p
	}

	topology := generateRandomTopology(mixes, 3)

	sharedRandomCommit := make(map[[pki.PublicKeyHashSize]byte][]byte)
	doc := &pki.Document{
		Version:            pki.DocumentVersion,
		Epoch:              epoch,
		GenesisEpoch:       epoch,
		Mu:                 0.25,
		MuMaxDelay:         4000,
		LambdaP:            1.2,
		LambdaPMaxDelay:    300,
		Topology:           topology,
		GatewayNodes:       gatewayDescriptors,
		ServiceNodes:       serviceDescriptors,
		SharedRandomCommit: sharedRandomCommit,
		SharedRandomValue:  make([]byte, pki.SharedRandomValueLength),
	}
	return doc, nil
}

// multiSignTestDocument signs and serializes the document with the provided signing key.
func multiSignTestDocument(signingKeys []sign.PrivateKey, signingPubKeys []sign.PublicKey, d *pki.Document) ([]byte, error) {
	// Serialize the document.
	opts := cbor.CanonicalEncOptions()
	ccbor, err := opts.EncMode()
	if err != nil {
		return nil, err
	}

	type document pki.Document
	payload, err := ccbor.Marshal((*document)(d))
	if err != nil {
		return nil, err
	}

	// Sign the document.
	current, _, _ := epochtime.Now()
	signed, err := cert.Sign(signingKeys[0], signingPubKeys[0], payload, current+4)
	if err != nil {
		return nil, err
	}
	for i := 1; i < len(signingKeys); i++ {
		signed, err = cert.SignMulti(signingKeys[i], signingPubKeys[i], signed)
	}
	return signed, nil
}

func generateDoc(epoch uint64, signingKeys []sign.PrivateKey, signingPubKeys []sign.PublicKey) ([]byte, error) {
	// XXX
	numMixes := len(signingKeys) - 2
	numProviders := 2
	doc, err := generateMixnet(numMixes, numProviders, epoch)
	if err != nil {
		return nil, err
	}
	signed, err := multiSignTestDocument(signingKeys, signingPubKeys, doc)
	if err != nil {
		return nil, err
	}
	return []byte(signed), nil
}

type conn struct {
	serverConn    net.Conn
	clientConn    net.Conn
	dialCh        chan interface{}
	signingKey    sign.PrivateKey
	signingPubKey sign.PublicKey
}

type mockDialer struct {
	sync.Mutex
	netMap map[string]*conn
	log    *logging.Logger
}

func newMockDialer(logBackend *log.Backend) *mockDialer {
	d := new(mockDialer)
	d.Lock()
	defer d.Unlock()

	d.netMap = make(map[string]*conn)

	d.log = logBackend.GetLogger("mockDialer: ")
	return d
}

func (d *mockDialer) dial(ctx context.Context, network string, address string) (net.Conn, error) {
	defer func() {
		d.Lock()
		close(d.netMap[address].dialCh)
		d.Unlock()
	}()
	d.log.Debug("MOCK DIAL %s", address)
	d.Lock()
	defer d.Unlock()
	return d.netMap[address].clientConn, nil
}

func (d *mockDialer) waitUntilDialed(address string) {
	d.Lock()
	if _, ok := d.netMap[address]; !ok {
		d.log.Errorf("address %s not found in mockDialer netMap", address)
		d.Unlock()
		return
	}
	dc := d.netMap[address].dialCh
	d.Unlock()
	<-dc
}

func (d *mockDialer) mockServer(address string, linkPrivateKey kem.PrivateKey, identityPrivateKey sign.PrivateKey,
	identityPublicKey sign.PublicKey, wg *sync.WaitGroup, mygeo *geo.Geometry) {
	d.Lock()
	d.log.Debugf("mockServer(%s)", address)

	clientConn, serverConn := net.Pipe()
	d.netMap[address] = &conn{
		serverConn:    serverConn,
		clientConn:    clientConn,
		dialCh:        make(chan interface{}, 0),
		signingKey:    identityPrivateKey,
		signingPubKey: identityPublicKey,
	}
	d.Unlock()
	wg.Done()

	d.waitUntilDialed(address)
	identityHash := hash.Sum256From(identityPublicKey)
	cfg := &wire.SessionConfig{
		KEMScheme:         testingScheme,
		Geometry:          mygeo,
		Authenticator:     d,
		AdditionalData:    identityHash[:],
		AuthenticationKey: linkPrivateKey,
		RandomReader:      rand.Reader,
	}
	session, err := wire.NewPKISession(cfg, false)
	if err != nil {
		d.log.Errorf("mockServer NewPKISession failure: %s", err)
		return
	}
	defer session.Close()
	d.Lock()
	err = session.Initialize(d.netMap[address].serverConn)
	d.Unlock()
	if err != nil {
		d.log.Errorf("mockServer session Initialize failure: %s", err)
		return
	}
	cmd, err := session.RecvCommand()
	if err != nil {
		d.log.Errorf("mockServer session RecvCommand failure: %s", err)
		return
	}
	switch c := cmd.(type) {
	case *commands.GetConsensus:
		signingKeys := []sign.PrivateKey{}
		signingPubKeys := []sign.PublicKey{}
		for _, v := range d.netMap {
			signingKeys = append(signingKeys, v.signingKey)
			signingPubKeys = append(signingPubKeys, v.signingPubKey)
		}
		rawDoc, err := generateDoc(c.Epoch, signingKeys, signingPubKeys)
		if err != nil {
			d.log.Errorf("mockServer session generateDoc failure: %s", err)
			return
		}
		reply := &commands.Consensus{
			ErrorCode: commands.ConsensusOk,
			Payload:   rawDoc,
		}
		err = session.SendCommand(reply)
		if err != nil {
			d.log.Errorf("SendCommand failure: %s", err)
			return
		}
	default:
		return
	}
}

func (d *mockDialer) IsPeerValid(creds *wire.PeerCredentials) bool {
	// XXX
	return true
}

func generatePeer(peerNum int) (*config.Authority, sign.PrivateKey, sign.PublicKey, kem.PrivateKey, error) {
	identityPublicKey, identityPrivateKey, err := testSignatureScheme.GenerateKey()
	if err != nil {
		return nil, nil, nil, nil, err
	}

	scheme := testingScheme
	linkPublicKey, linkPrivateKey, err := scheme.GenerateKeyPair()
	if err != nil {
		return nil, nil, nil, nil, err
	}

	authPeer := &config.Authority{
		Identifier:        fmt.Sprintf("authority%d", peerNum),
		WireKEMScheme:     testingSchemeName,
		IdentityPublicKey: identityPublicKey,
		LinkPublicKey:     linkPublicKey,
		Addresses:         []string{fmt.Sprintf("tcp://127.0.0.1:%d", peerNum)},
	}
	err = authPeer.Validate()
	if err != nil {
		return nil, nil, nil, nil, err
	}
	return authPeer, identityPrivateKey, identityPublicKey, linkPrivateKey, nil
}

func TestClient(t *testing.T) {
	t.Parallel()
	require := require.New(t)

	logBackend, err := log.New("", "DEBUG", false)
	require.NoError(err)
	dialer := newMockDialer(logBackend)
	peers := []*config.Authority{}

	mynike := ecdh.Scheme(rand.Reader)
	mygeo := geo.GeometryFromUserForwardPayloadLength(mynike, 2000, true, 5)

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		peer, idPrivKey, idPubKey, linkPrivKey, err := generatePeer(i)
		require.NoError(err)
		peers = append(peers, peer)
		wg.Add(1)
		u, _ := url.Parse(peer.Addresses[0])
		go dialer.mockServer(u.Host, linkPrivKey, idPrivKey, idPubKey, &wg, mygeo)
	}
	wg.Wait()
	cfg := &Config{
		KEMScheme:     testingScheme,
		LogBackend:    logBackend,
		Authorities:   peers,
		DialContextFn: dialer.dial,
		Geo:           mygeo,
	}
	client, err := New(cfg)
	require.NoError(err)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*100)
	defer cancel()
	epoch, _, _ := epochtime.Now()
	doc, rawDoc, err := client.GetPKIDocumentForEpoch(ctx, epoch)
	require.NoError(err)
	require.NotNil(doc)
	require.Equal(epoch, doc.Epoch)
	t.Logf("rawDoc size is %d", len(rawDoc))
}

// delayDialer wraps mockDialer to add configurable delays and failure modes
type delayDialer struct {
	delays      map[string]time.Duration
	failures    map[string]bool
	dialCount   int32
	contactTime sync.Map // records first contact time per address
	mu          sync.Mutex
}

func newDelayDialer() *delayDialer {
	return &delayDialer{
		delays:   make(map[string]time.Duration),
		failures: make(map[string]bool),
	}
}

func (d *delayDialer) dial(ctx context.Context, network, address string) (net.Conn, error) {
	d.contactTime.LoadOrStore(address, time.Now())
	atomic.AddInt32(&d.dialCount, 1)

	d.mu.Lock()
	delay := d.delays[address]
	fail := d.failures[address]
	d.mu.Unlock()

	if fail {
		return nil, fmt.Errorf("simulated failure to %s", address)
	}
	if delay > 0 {
		select {
		case <-time.After(delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	c, _ := net.Pipe()
	return c, nil
}

// TestParallelAuthorityContact verifies authorities are contacted concurrently
func TestParallelAuthorityContact(t *testing.T) {
	t.Parallel()
	require := require.New(t)

	logBackend, err := log.New("", "DEBUG", false)
	require.NoError(err)

	dialer := newDelayDialer()
	var peers []*config.Authority
	// 3 fast + 2 slow (would block if sequential)
	for i := 0; i < 5; i++ {
		peer, _, _, _, err := generatePeer(10000 + i)
		require.NoError(err)
		peers = append(peers, peer)
		u, _ := url.Parse(peer.Addresses[0])
		if i >= 3 {
			dialer.delays[u.Host] = 5 * time.Second // slow but within context timeout
		}
	}

	mynike := ecdh.Scheme(rand.Reader)
	mygeo := geo.GeometryFromUserForwardPayloadLength(mynike, 2000, true, 5)

	cfg := &Config{
		KEMScheme:           testingScheme,
		LogBackend:          logBackend,
		Authorities:         peers,
		DialContextFn:       dialer.dial,
		Geo:                 mygeo,
		DialTimeoutSec:      1,
		HandshakeTimeoutSec: 1,
		ResponseTimeoutSec:  1,
		RetryMaxAttempts:    1, // No retries - fail fast
	}
	require.NoError(cfg.validate())
	conn := newConnector(cfg)

	// Context shorter than slow delay - parallel will timeout fast, sequential would block
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	_, linkKey, _ := testingScheme.GenerateKeyPair()
	start := time.Now()
	conn.allPeersRoundTrip(ctx, linkKey, nil, &commands.GetConsensus{Epoch: 1})
	elapsed := time.Since(start)

	// If parallel, all 5 contacted simultaneously, completes in ~2s (context timeout)
	// If sequential with 2 slow nodes at 5s each, would take 10s+ just for dial
	require.Less(elapsed, 3*time.Second, "authorities not contacted in parallel")
	t.Logf("parallel contact completed in %v", elapsed)
}

// TestParallelFailingAuthorities verifies failures don't block other authorities
func TestParallelFailingAuthorities(t *testing.T) {
	t.Parallel()
	require := require.New(t)

	logBackend, err := log.New("", "DEBUG", false)
	require.NoError(err)

	dialer := newDelayDialer()
	var peers []*config.Authority
	for i := 0; i < 5; i++ {
		peer, _, _, _, err := generatePeer(20000 + i)
		require.NoError(err)
		peers = append(peers, peer)
		u, _ := url.Parse(peer.Addresses[0])
		if i >= 3 {
			dialer.failures[u.Host] = true // 2 will fail immediately at dial
		}
	}

	mynike := ecdh.Scheme(rand.Reader)
	mygeo := geo.GeometryFromUserForwardPayloadLength(mynike, 2000, true, 5)

	cfg := &Config{
		KEMScheme:           testingScheme,
		LogBackend:          logBackend,
		Authorities:         peers,
		DialContextFn:       dialer.dial,
		Geo:                 mygeo,
		DialTimeoutSec:      1,
		HandshakeTimeoutSec: 1,
		ResponseTimeoutSec:  1,
		RetryMaxAttempts:    1, // No retries - fail fast
	}
	require.NoError(cfg.validate())
	conn := newConnector(cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	_, linkKey, _ := testingScheme.GenerateKeyPair()
	start := time.Now()
	responses, err := conn.allPeersRoundTrip(ctx, linkKey, nil, &commands.GetConsensus{Epoch: 1})
	elapsed := time.Since(start)

	require.NoError(err)
	require.Len(responses, 5)
	require.Less(elapsed, 3*time.Second, "failing authorities blocked operation")

	var failCount int
	for _, r := range responses {
		if r.Error != nil {
			failCount++
		}
	}
	require.GreaterOrEqual(failCount, 2, "expected at least 2 failures")
	t.Logf("got %d failures in %v", failCount, elapsed)
}

// TestParallelContextCancellation verifies context cancellation stops goroutines
func TestParallelContextCancellation(t *testing.T) {
	t.Parallel()
	require := require.New(t)

	logBackend, err := log.New("", "DEBUG", false)
	require.NoError(err)

	dialer := newDelayDialer()
	var peers []*config.Authority
	for i := 0; i < 5; i++ {
		peer, _, _, _, err := generatePeer(30000 + i)
		require.NoError(err)
		peers = append(peers, peer)
		u, _ := url.Parse(peer.Addresses[0])
		dialer.delays[u.Host] = 30 * time.Second // all very slow
	}

	mynike := ecdh.Scheme(rand.Reader)
	mygeo := geo.GeometryFromUserForwardPayloadLength(mynike, 2000, true, 5)

	cfg := &Config{
		KEMScheme:           testingScheme,
		LogBackend:          logBackend,
		Authorities:         peers,
		DialContextFn:       dialer.dial,
		Geo:                 mygeo,
		DialTimeoutSec:      60,
		HandshakeTimeoutSec: 60,
		ResponseTimeoutSec:  60,
		RetryMaxAttempts:    1, // No retries
	}
	require.NoError(cfg.validate())
	conn := newConnector(cfg)

	// Very short context - should cancel quickly
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	_, linkKey, _ := testingScheme.GenerateKeyPair()
	start := time.Now()
	conn.allPeersRoundTrip(ctx, linkKey, nil, &commands.GetConsensus{Epoch: 1})
	elapsed := time.Since(start)

	require.Less(elapsed, 1*time.Second, "context cancellation didn't stop operations")
	t.Logf("cancelled in %v", elapsed)
}

// TestRetryDefaults verifies retry module defaults are used
func TestRetryDefaults(t *testing.T) {
	t.Parallel()
	require := require.New(t)

	logBackend, err := log.New("", "DEBUG", false)
	require.NoError(err)

	cfg := &Config{
		KEMScheme:  testingScheme,
		LogBackend: logBackend,
	}
	require.NoError(cfg.validate())

	require.Equal(retry.DefaultMaxAttempts, cfg.RetryMaxAttempts)
	require.Equal(retry.DefaultBaseDelay, cfg.RetryBaseDelay)
	require.Equal(retry.DefaultMaxDelay, cfg.RetryMaxDelay)
	require.Equal(retry.DefaultJitter, cfg.RetryJitter)
}

// immediateCloseDialer returns a connection that closes immediately to simulate EOF
type immediateCloseDialer struct {
	dialCount int32
}

func (d *immediateCloseDialer) dial(ctx context.Context, network, address string) (net.Conn, error) {
	atomic.AddInt32(&d.dialCount, 1)
	client, server := net.Pipe()
	// Close the server side immediately to cause EOF on client read
	server.Close()
	return client, nil
}

// TestHandshakeDebugErrorOnEOF verifies that EOF during handshake produces a DebugError
func TestHandshakeDebugErrorOnEOF(t *testing.T) {
	t.Parallel()
	require := require.New(t)

	logBackend, err := log.New("", "DEBUG", false)
	require.NoError(err)

	dialer := &immediateCloseDialer{}
	peer, _, _, _, err := generatePeer(40000)
	require.NoError(err)

	mynike := ecdh.Scheme(rand.Reader)
	mygeo := geo.GeometryFromUserForwardPayloadLength(mynike, 2000, true, 5)

	cfg := &Config{
		KEMScheme:           testingScheme,
		LogBackend:          logBackend,
		Authorities:         []*config.Authority{peer},
		DialContextFn:       dialer.dial,
		Geo:                 mygeo,
		DialTimeoutSec:      5,
		HandshakeTimeoutSec: 5,
		ResponseTimeoutSec:  5,
		RetryMaxAttempts:    0, // No retries
	}
	require.NoError(cfg.validate())
	conn := newConnector(cfg)

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	_, linkKey, _ := testingScheme.GenerateKeyPair()
	responses, err := conn.allPeersRoundTrip(ctx, linkKey, nil, &commands.GetConsensus{Epoch: 1})
	require.NoError(err)
	require.Len(responses, 1)

	// The response should have an error from the handshake failure
	resp := responses[0]
	require.NotNil(resp.Error, "expected handshake error")

	// Get the debug error output
	debugOutput := wire.GetDebugError(resp.Error)
	t.Logf("Debug error output:\n%s", debugOutput)

	// Verify the error contains expected debug information
	// The error should be wrapped and contain handshake state info
	require.Contains(resp.Error.Error(), "handshake failed", "error should mention handshake")
}

// hangingDialer creates connections where the server never responds
type hangingDialer struct {
	conns []*net.Conn
	mu    sync.Mutex
}

func (d *hangingDialer) dial(ctx context.Context, network, address string) (net.Conn, error) {
	client, server := net.Pipe()
	d.mu.Lock()
	d.conns = append(d.conns, &server)
	d.mu.Unlock()
	// Server never responds - handshake will timeout or get EOF
	return client, nil
}

func (d *hangingDialer) closeAll() {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, c := range d.conns {
		(*c).Close()
	}
}

// TestHandshakeDebugErrorContainsStateInfo verifies the wrapped error has state info
// Note: The connector wraps errors with additional context, so the returned error
// doesn't implement DebugError directly. However, the connector internally calls
// wire.GetDebugError() on the raw error and logs it at DEBUG level before wrapping.
// This test verifies that the returned error contains the detailed handshake state info.
func TestHandshakeDebugErrorContainsStateInfo(t *testing.T) {
	t.Parallel()
	require := require.New(t)

	logBackend, err := log.New("", "DEBUG", false)
	require.NoError(err)

	dialer := &hangingDialer{}
	defer dialer.closeAll()

	peer, _, _, _, err := generatePeer(41000)
	require.NoError(err)

	mynike := ecdh.Scheme(rand.Reader)
	mygeo := geo.GeometryFromUserForwardPayloadLength(mynike, 2000, true, 5)

	cfg := &Config{
		KEMScheme:           testingScheme,
		LogBackend:          logBackend,
		Authorities:         []*config.Authority{peer},
		DialContextFn:       dialer.dial,
		Geo:                 mygeo,
		DialTimeoutSec:      1,
		HandshakeTimeoutSec: 1, // Short timeout to make test fast
		ResponseTimeoutSec:  1,
		RetryMaxAttempts:    1, // Only 1 attempt (no retries)
	}
	require.NoError(cfg.validate())
	conn := newConnector(cfg)

	// Use a longer context so we don't get context deadline exceeded
	// but the handshake timeout will still trigger
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	_, linkKey, _ := testingScheme.GenerateKeyPair()
	responses, err := conn.allPeersRoundTrip(ctx, linkKey, nil, &commands.GetConsensus{Epoch: 1})
	require.NoError(err)
	require.Len(responses, 1)

	resp := responses[0]
	require.NotNil(resp.Error, "expected handshake timeout/EOF error")

	// The error is wrapped by the connector, but should still contain the
	// HandshakeError's detailed Error() output with state info
	errStr := resp.Error.Error()
	t.Logf("Error string: %s", errStr)

	// The error should contain:
	// 1. "handshake failed" from the connector wrapper
	// 2. State info from HandshakeError.Error() (e.g., "message_1_send", "initiator")
	require.Contains(errStr, "handshake failed", "error should mention handshake failed")
	require.Contains(errStr, "message_1_send", "error should contain handshake state")
	require.Contains(errStr, "initiator", "error should indicate role")
	require.Contains(errStr, "i/o timeout", "error should contain underlying error")
}

// wrongVersionDialer simulates a server sending wrong protocol version
type wrongVersionDialer struct{}

func (d *wrongVersionDialer) dial(ctx context.Context, network, address string) (net.Conn, error) {
	client, server := net.Pipe()
	go func() {
		// Send garbage that doesn't match expected protocol version
		server.Write([]byte{0x99, 0x99, 0x99})
		// Keep connection open briefly so client can read
		time.Sleep(100 * time.Millisecond)
		server.Close()
	}()
	return client, nil
}

// TestHandshakeDebugErrorFormats verifies GetDebugError returns formatted output
func TestHandshakeDebugErrorFormats(t *testing.T) {
	t.Parallel()
	require := require.New(t)

	// Test that HandshakeError.Debug() produces expected format
	herr := &wire.HandshakeError{
		State:           wire.HandshakeStateMsg2Receive,
		Message:         "failed to receive message 2",
		UnderlyingError: fmt.Errorf("unexpected EOF"),
		IsInitiator:     true,
		ProtocolName:    "pqXX",
		KEMScheme:       testingSchemeName,
		MessageNumber:   2,
		ExpectedSize:    1234,
	}

	// Test Error() method - should be safe for non-debug logging
	errStr := herr.Error()
	t.Logf("Error(): %s", errStr)
	require.Contains(errStr, "message_2_receive")
	require.Contains(errStr, "initiator")
	require.Contains(errStr, "failed to receive message 2")
	require.Contains(errStr, "unexpected EOF")

	// Test Debug() method - should contain detailed info
	debugStr := herr.Debug()
	t.Logf("Debug():\n%s", debugStr)
	require.Contains(debugStr, "=== WIRE PROTOCOL HANDSHAKE FAILURE ===")
	require.Contains(debugStr, "message_2_receive")
	require.Contains(debugStr, "initiator")
	require.Contains(debugStr, "pqXX")
	require.Contains(debugStr, testingSchemeName)
	require.Contains(debugStr, "Message Number: 2")
	require.Contains(debugStr, "Expected Size: 1234")

	// Test GetDebugError with a HandshakeError
	var err error = herr
	debugOutput := wire.GetDebugError(err)
	require.Equal(debugStr, debugOutput, "GetDebugError should return Debug() for HandshakeError")

	// Test GetDebugError with a regular error (should just return Error())
	regularErr := fmt.Errorf("regular error")
	regularDebug := wire.GetDebugError(regularErr)
	require.Equal("regular error", regularDebug, "GetDebugError should return Error() for regular errors")
}

// TestAuthenticationErrorDebugFormat verifies AuthenticationError debug output
func TestAuthenticationErrorDebugFormat(t *testing.T) {
	t.Parallel()
	require := require.New(t)

	authErr := &wire.AuthenticationError{
		PeerCredentials: &wire.PeerCredentials{
			AdditionalData: []byte{0x01, 0x02, 0x03},
		},
		AdditionalData: []byte{0x04, 0x05, 0x06},
	}

	// Test Error() - should not contain sensitive data
	errStr := authErr.Error()
	t.Logf("Error(): %s", errStr)
	require.Contains(errStr, "authentication failed")

	// Test Debug() - should contain detailed info
	debugStr := authErr.Debug()
	t.Logf("Debug():\n%s", debugStr)
	require.Contains(debugStr, "=== PEER AUTHENTICATION FAILURE ===")

	// Test GetDebugError
	var err error = authErr
	debugOutput := wire.GetDebugError(err)
	require.Equal(debugStr, debugOutput)
}

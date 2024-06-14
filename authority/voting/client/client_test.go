// client.go - Katzenpost voting authority client.
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
	"sync"
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
				"tcp4": []string{fmt.Sprintf("127.0.0.1:%d", i+1)},
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
	session, err := wire.NewSession(cfg, false)
	if err != nil {
		d.log.Errorf("mockServer NewSession failure: %s", err)
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
		WireKEMScheme:     testingSchemeName,
		IdentityPublicKey: identityPublicKey,
		LinkPublicKey:     linkPublicKey,
		Addresses:         []string{fmt.Sprintf("127.0.0.1:%d", peerNum)},
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
		go dialer.mockServer(peer.Addresses[0], linkPrivKey, idPrivKey, idPubKey, &wg, mygeo)
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
	doc, rawDoc, err := client.Get(ctx, epoch)
	require.NoError(err)
	require.NotNil(doc)
	require.Equal(epoch, doc.Epoch)
	t.Logf("rawDoc size is %d", len(rawDoc))
}

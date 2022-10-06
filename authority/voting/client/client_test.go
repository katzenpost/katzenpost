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
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/ugorji/go/codec"
	"gopkg.in/op/go-logging.v1"

	"github.com/katzenpost/katzenpost/authority/internal/s11n"
	"github.com/katzenpost/katzenpost/authority/voting/server/config"
	"github.com/katzenpost/katzenpost/core/crypto/cert"
	"github.com/katzenpost/katzenpost/core/crypto/ecdh"
	"github.com/katzenpost/katzenpost/core/crypto/pem"
	"github.com/katzenpost/katzenpost/core/crypto/rand"
	"github.com/katzenpost/katzenpost/core/crypto/sign"
	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/sphinx"
	"github.com/katzenpost/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/katzenpost/core/wire"
	"github.com/katzenpost/katzenpost/core/wire/commands"
)

type descriptor struct {
	desc *pki.MixDescriptor
	raw  []byte
}

func generateRandomTopology(nodes []*descriptor, layers int) [][][]byte {
	rng := rand.NewMath()
	nodeIndexes := rng.Perm(len(nodes))
	topology := make([][][]byte, layers)
	for idx, layer := 0, 0; idx < len(nodes); idx++ {
		n := nodes[nodeIndexes[idx]]
		topology[layer] = append(topology[layer], n.raw)
		layer++
		layer = layer % len(topology)
	}
	return topology
}

func generateTopology(nodeList []*descriptor, doc *pki.Document, layers int) [][][]byte {
	nodeMap := make(map[[constants.NodeIDLength]byte]*descriptor)
	for _, v := range nodeList {
		id := v.desc.IdentityKey.Sum256()
		nodeMap[id] = v
	}

	// Since there is an existing network topology, use that as the basis for
	// generating the mix topology such that the number of nodes per layer is
	// approximately equal, and as many nodes as possible retain their existing
	// layer assignment to minimise network churn.

	rng := rand.NewMath()
	targetNodesPerLayer := len(nodeList) / layers
	topology := make([][][]byte, layers)

	// Assign nodes that still exist up to the target size.
	for layer, nodes := range doc.Topology {
		//nodeIndexes := rng.Perm(len(nodes))
		nodeIndexes := rng.Perm(len(nodes))

		for _, idx := range nodeIndexes {
			if len(topology[layer]) >= targetNodesPerLayer {
				break
			}

			id := nodes[idx].IdentityKey.Sum256()
			if n, ok := nodeMap[id]; ok {
				// There is a new descriptor with the same identity key,
				// as an existing descriptor in the previous document,
				// so preserve the layering.
				topology[layer] = append(topology[layer], n.raw)
				delete(nodeMap, id)
			}
		}
	}

	// Flatten the map containing the nodes pending assignment.
	toAssign := make([]*descriptor, 0, len(nodeMap))
	for _, n := range nodeMap {
		toAssign = append(toAssign, n)
	}
	assignIndexes := rng.Perm(len(toAssign))

	// Fill out any layers that are under the target size, by
	// randomly assigning from the pending list.
	idx := 0
	for layer := range doc.Topology {
		for len(topology[layer]) < targetNodesPerLayer {
			n := toAssign[assignIndexes[idx]]
			topology[layer] = append(topology[layer], n.raw)
			idx++
		}
	}

	// Assign the remaining nodes.
	for layer := 0; idx < len(assignIndexes); idx++ {
		n := toAssign[assignIndexes[idx]]
		topology[layer] = append(topology[layer], n.raw)
		layer++
		layer = layer % len(topology)
	}

	return topology
}

func generateMixKeys(epoch uint64) (map[uint64]*ecdh.PublicKey, error) {
	m := make(map[uint64]*ecdh.PublicKey)
	for i := epoch; i < epoch+3; i++ {
		privatekey, err := ecdh.NewKeypair(rand.Reader)
		if err != nil {
			return nil, err
		}
		m[uint64(i)] = privatekey.PublicKey()
	}
	return m, nil
}

func generateNodes(isProvider bool, num int, epoch uint64) ([]*descriptor, error) {
	mixes := []*descriptor{}
	for i := 0; i < num; i++ {
		mixIdentityPrivateKey, mixIdentityPublicKey := cert.Scheme.NewKeypair()
		mixKeys, err := generateMixKeys(epoch)
		if err != nil {
			return nil, err
		}
		var layer uint8
		var name string
		if isProvider {
			layer = pki.LayerProvider
			name = fmt.Sprintf("NSA_Spy_Satelite_Provider%d", i)
		} else {
			layer = 0
			name = fmt.Sprintf("NSA_Spy_Satelite_Mix%d", i)
		}

		scheme := wire.DefaultScheme
		linkKey := scheme.GenerateKeypair(rand.Reader)

		mix := &pki.MixDescriptor{
			Name:        name,
			IdentityKey: mixIdentityPublicKey,
			LinkKey:     linkKey.PublicKey(),
			MixKeys:     mixKeys,
			Addresses: map[pki.Transport][]string{
				pki.Transport("tcp4"): []string{fmt.Sprintf("127.0.0.1:%d", i+1)},
			},
			Kaetzchen:  nil,
			Layer:      layer,
			LoadWeight: 0,
		}
		signed, err := s11n.SignDescriptor(mixIdentityPrivateKey, mix)
		if err != nil {
			return nil, err
		}
		desc := &descriptor{
			raw:  []byte(signed),
			desc: mix,
		}
		mixes = append(mixes, desc)
	}
	return mixes, nil
}

func generateMixnet(numMixes, numProviders int, epoch uint64) (*s11n.Document, error) {
	mixes, err := generateNodes(false, numMixes, epoch)
	if err != nil {
		return nil, err
	}
	providers, err := generateNodes(true, numProviders, epoch)
	if err != nil {
		return nil, err
	}
	providersRaw := [][]byte{}
	for _, p := range providers {
		providersRaw = append(providersRaw, p.raw)
	}
	topology := generateRandomTopology(mixes, 3)

	sharedRandomCommit := make([]byte, s11n.SharedRandomLength)
	binary.BigEndian.PutUint64(sharedRandomCommit[:8], epoch)
	doc := &s11n.Document{
		Version:            s11n.DocumentVersion,
		Epoch:              epoch,
		GenesisEpoch:       epoch,
		Mu:                 0.25,
		MuMaxDelay:         4000,
		LambdaP:            1.2,
		LambdaPMaxDelay:    300,
		Topology:           topology,
		Providers:          providersRaw,
		SharedRandomCommit: sharedRandomCommit,
		SharedRandomValue:  make([]byte, s11n.SharedRandomValueLength),
	}
	return doc, nil
}

// multiSignTestDocument signs and serializes the document with the provided signing key.
func multiSignTestDocument(signingKeys []sign.PrivateKey, d *s11n.Document) ([]byte, error) {
	jsonHandle := new(codec.JsonHandle)
	jsonHandle.Canonical = true
	jsonHandle.IntegerAsString = 'A'
	jsonHandle.MapKeyAsString = true

	d.Version = s11n.DocumentVersion
	// Serialize the document.
	var payload []byte
	enc := codec.NewEncoderBytes(&payload, jsonHandle)
	if err := enc.Encode(d); err != nil {
		return nil, err
	}

	// Sign the document.
	expiration := time.Now().Add(s11n.CertificateExpiration).Unix()
	signed, err := cert.Sign(signingKeys[0], payload, expiration)
	if err != nil {
		return nil, err
	}
	for i := 1; i < len(signingKeys); i++ {
		signed, err = cert.SignMulti(signingKeys[i], signed)
	}
	return signed, nil
}

func generateDoc(epoch uint64, signingKeys []sign.PrivateKey) ([]byte, error) {
	// XXX
	numMixes := len(signingKeys) - 2
	numProviders := 2
	doc, err := generateMixnet(numMixes, numProviders, epoch)
	if err != nil {
		return nil, err
	}
	signed, err := multiSignTestDocument(signingKeys, doc)
	if err != nil {
		return nil, err
	}
	return []byte(signed), nil
}

type conn struct {
	serverConn net.Conn
	clientConn net.Conn
	dialCh     chan interface{}
	signingKey sign.PrivateKey
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
	d.Lock()
	defer func() {
		d.Lock()
		defer d.Unlock()
		close(d.netMap[address].dialCh)
	}()
	defer d.Unlock()
	d.log.Debug("MOCK DIAL %s", address)
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

func (d *mockDialer) mockServer(address string, linkPrivateKey wire.PrivateKey, identityPrivateKey sign.PrivateKey, identityPublicKey sign.PublicKey, wg *sync.WaitGroup) {
	d.Lock()
	clientConn, serverConn := net.Pipe()
	d.netMap[address] = &conn{
		serverConn: serverConn,
		clientConn: clientConn,
		dialCh:     make(chan interface{}, 0),
		signingKey: identityPrivateKey,
	}
	d.Unlock()
	wg.Done()

	d.waitUntilDialed(address)
	identityHash := identityPublicKey.Sum256()
	cfg := &wire.SessionConfig{
		Geometry:          &sphinx.Geometry{},
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
		for _, v := range d.netMap {
			signingKeys = append(signingKeys, v.signingKey)
		}
		rawDoc, err := generateDoc(c.Epoch, signingKeys)
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

func generatePeer(peerNum int, datadir string) (*config.AuthorityPeer, sign.PrivateKey, sign.PublicKey, wire.PrivateKey, error) {
	identityPrivateKey, identityPublicKey := cert.Scheme.NewKeypair()
	identityPublicKeyPem := filepath.Join(datadir, fmt.Sprintf("peer%d_id_pub_key.pem", peerNum))
	err := pem.ToFile(identityPublicKeyPem, identityPublicKey)
	if err != nil {
		panic(err)
	}

	scheme := wire.DefaultScheme
	linkPrivateKey := scheme.GenerateKeypair(rand.Reader)
	err = scheme.PrivateKeyToPemFile(filepath.Join(datadir, fmt.Sprintf("peer%d_link_priv_key.pem", peerNum)), linkPrivateKey)
	if err != nil {
		panic(err)
	}
	err = scheme.PublicKeyToPemFile(filepath.Join(datadir, fmt.Sprintf("peer%d_link_pub_key.pem", peerNum)), linkPrivateKey.PublicKey())
	if err != nil {
		panic(err)
	}
	authPeer := &config.AuthorityPeer{
		IdentityPublicKeyPem: fmt.Sprintf("peer%d_id_pub_key.pem", peerNum),
		LinkPublicKeyPem:     fmt.Sprintf("peer%d_link_pub_key.pem", peerNum),
		Addresses:            []string{fmt.Sprintf("127.0.0.1:%d", peerNum)},
	}
	err = authPeer.Validate(datadir)
	if err != nil {
		panic(err)
	}
	return authPeer, identityPrivateKey, identityPublicKey, linkPrivateKey, nil
}

func TestClient(t *testing.T) {
	require := require.New(t)

	logBackend, err := log.New("", "DEBUG", false)
	require.NoError(err)
	dialer := newMockDialer(logBackend)
	peers := []*config.AuthorityPeer{}

	datadir := os.TempDir()

	var wg sync.WaitGroup
	for i := 0; i < 10; i++ {
		peer, idPrivKey, idPubKey, linkPrivKey, err := generatePeer(i, datadir)
		require.NoError(err)
		peers = append(peers, peer)
		wg.Add(1)
		go dialer.mockServer(peer.Addresses[0], linkPrivKey, idPrivKey, idPubKey, &wg)
	}
	wg.Wait()
	cfg := &Config{
		DataDir:       datadir,
		LogBackend:    logBackend,
		Authorities:   peers,
		DialContextFn: dialer.dial,
	}
	client, err := New(cfg)
	require.NoError(err)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()
	epoch, _, _ := epochtime.Now()
	doc, rawDoc, err := client.Get(ctx, epoch)
	require.NoError(err)
	require.NotNil(doc)
	require.Equal(epoch, doc.Epoch)
	t.Logf("rawDoc size is %d", len(rawDoc))
}

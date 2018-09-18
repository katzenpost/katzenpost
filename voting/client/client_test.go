// client.go - Katzenpost non-voting authority client.
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

// Package client implements the Katzenpost non-voting authority client.
package client

import (
	"context"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/katzenpost/authority/voting/internal/s11n"
	"github.com/katzenpost/authority/voting/server/config"
	"github.com/katzenpost/core/crypto/ecdh"
	"github.com/katzenpost/core/crypto/eddsa"
	"github.com/katzenpost/core/crypto/rand"
	"github.com/katzenpost/core/epochtime"
	"github.com/katzenpost/core/log"
	"github.com/katzenpost/core/pki"
	"github.com/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/core/wire"
	"github.com/katzenpost/core/wire/commands"
	"github.com/stretchr/testify/require"
	"gopkg.in/op/go-logging.v1"
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
		id := v.desc.IdentityKey.ByteArray()
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

			id := nodes[idx].IdentityKey.ByteArray()
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
		mixIdentityPrivateKey, err := eddsa.NewKeypair(rand.Reader)
		if err != nil {
			return nil, err
		}
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
		mix := &pki.MixDescriptor{
			Name:        name,
			IdentityKey: mixIdentityPrivateKey.PublicKey(),
			LinkKey:     mixIdentityPrivateKey.PublicKey().ToECDH(),
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
	doc := &s11n.Document{
		Version:         "voting-document-v0",
		Epoch:           epoch,
		MixLambda:       0.25,
		MixMaxDelay:     4000,
		SendLambda:      1.2,
		SendShift:       3,
		SendMaxInterval: 300,
		Topology:        topology,
		Providers:       providersRaw,
	}
	return doc, nil
}

func generateDoc(epoch uint64, signingKeys []*eddsa.PrivateKey) ([]byte, error) {
	// XXX
	numMixes := len(signingKeys) - 2
	numProviders := 2
	doc, err := generateMixnet(numMixes, numProviders, epoch)
	if err != nil {
		return nil, err
	}
	signed, err := s11n.MultiSignTestDocument(signingKeys, doc)
	if err != nil {
		return nil, err
	}
	return []byte(signed), nil
}

type conn struct {
	serverConn net.Conn
	clientConn net.Conn
	dialCh     chan interface{}
	signingKey *eddsa.PrivateKey
}

type mockDialer struct {
	sync.Mutex
	netMap map[string]*conn
	log    *logging.Logger
}

func newMockDialer(logBackend *log.Backend) *mockDialer {
	d := new(mockDialer)
	d.netMap = make(map[string]*conn)

	d.log = logBackend.GetLogger("mockDialer: ")
	return d
}

func (d *mockDialer) dial(ctx context.Context, network string, address string) (net.Conn, error) {
	d.Lock()
	defer d.Unlock()
	defer func() {
		close(d.netMap[address].dialCh)
	}()
	d.log.Debug("MOCK DIAL %s", address)
	return d.netMap[address].clientConn, nil
}

func (d *mockDialer) waitUntilDialed(address string) {
	if _, ok := d.netMap[address]; !ok {
		d.log.Errorf("address %s not found in mockDialer netMap", address)
		return
	}
	<-d.netMap[address].dialCh
}

func (d *mockDialer) mockServer(address string, linkPrivateKey *ecdh.PrivateKey, identityPrivateKey *eddsa.PrivateKey) {
	clientConn, serverConn := net.Pipe()
	d.netMap[address] = &conn{
		serverConn: serverConn,
		clientConn: clientConn,
		dialCh:     make(chan interface{}, 0),
		signingKey: identityPrivateKey,
	}

	d.waitUntilDialed(address)
	cfg := &wire.SessionConfig{
		Authenticator:     d,
		AdditionalData:    identityPrivateKey.PublicKey().Bytes(),
		AuthenticationKey: linkPrivateKey,
		RandomReader:      rand.Reader,
	}
	session, err := wire.NewSession(cfg, false)
	if err != nil {
		d.log.Errorf("mockServer NewSession failure: %s", err)
		return
	}
	defer session.Close()
	err = session.Initialize(d.netMap[address].serverConn)
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
		signingKeys := []*eddsa.PrivateKey{}
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

func generatePeer(peerNum int) (*config.AuthorityPeer, *eddsa.PrivateKey, *ecdh.PrivateKey, error) {
	identityPrivateKey, err := eddsa.NewKeypair(rand.Reader)
	if err != nil {
		return nil, nil, nil, err
	}
	linkPrivateKey := identityPrivateKey.ToECDH()
	return &config.AuthorityPeer{
		IdentityPublicKey: identityPrivateKey.PublicKey(),
		LinkPublicKey:     linkPrivateKey.PublicKey(),
		Addresses:         []string{fmt.Sprintf("127.0.0.1:%d", peerNum)},
	}, identityPrivateKey, linkPrivateKey, nil
}

func TestClient(t *testing.T) {
	require := require.New(t)

	logBackend, err := log.New("", "DEBUG", false)
	require.NoError(err)
	dialer := newMockDialer(logBackend)
	peers := []*config.AuthorityPeer{}
	for i := 0; i < 10; i++ {
		peer, idPrivKey, linkPrivKey, err := generatePeer(i)
		require.NoError(err)
		peers = append(peers, peer)
		go dialer.mockServer(peer.Addresses[0], linkPrivKey, idPrivKey)
	}
	cfg := &Config{
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

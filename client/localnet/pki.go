// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package localnet

import (
	"fmt"
	"sync"

	"github.com/katzenpost/hpqc/hash"
	"github.com/katzenpost/hpqc/kem"
	kemSchemes "github.com/katzenpost/hpqc/kem/schemes"
	"github.com/katzenpost/hpqc/nike"
	nikeSchemes "github.com/katzenpost/hpqc/nike/schemes"
	"github.com/katzenpost/hpqc/sign"
	signSchemes "github.com/katzenpost/hpqc/sign/schemes"

	"github.com/katzenpost/katzenpost/core/cert"
	"github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
)

const (
	signSchemeName = "Ed25519"
	wireKEMName    = "Xwing"
	mixNIKEName    = "x25519"

	// mixLayers is the number of mix layers between gateway and service
	// node. With the gateway and service node it fills the 5 hops of the
	// Sphinx geometry, as on the docker mixnet.
	mixLayers = 3

	// epochSpan is how many epochs either side of a document's own
	// carry mix keys, so a path built near an epoch boundary still finds
	// keys for every hop.
	epochSpan = 2
)

var (
	signScheme = signSchemes.ByName(signSchemeName)
	wireKEM    = kemSchemes.ByName(wireKEMName)
	mixNIKE    = nikeSchemes.ByName(mixNIKEName)
)

// node is a mix, gateway or service node: its descriptor without epoch
// data, and the Sphinx key it unwraps packets with in every epoch.
type node struct {
	desc     pki.MixDescriptor
	idHash   [32]byte
	mixPub   []byte
	mixPriv  nike.PrivateKey
	linkPriv kem.PrivateKey
}

func newNode(name string) (*node, error) {
	idPub, _, err := signScheme.GenerateKey()
	if err != nil {
		return nil, err
	}
	idBytes, err := idPub.MarshalBinary()
	if err != nil {
		return nil, err
	}
	linkPub, linkPriv, err := wireKEM.GenerateKeyPair()
	if err != nil {
		return nil, err
	}
	linkBytes, err := linkPub.MarshalBinary()
	if err != nil {
		return nil, err
	}
	mixPub, mixPriv, err := mixNIKE.GenerateKeyPair()
	if err != nil {
		return nil, err
	}
	return &node{
		desc: pki.MixDescriptor{
			Name:        name,
			IdentityKey: idBytes,
			LinkKey:     linkBytes,
			Addresses:   map[string][]string{"tcp": {"tcp://127.0.0.1:1"}},
			Version:     pki.DescriptorVersion,
		},
		idHash:   hash.Sum256(idBytes),
		mixPub:   mixPub.Bytes(),
		mixPriv:  mixPriv,
		linkPriv: linkPriv,
	}, nil
}

// descriptor returns the node's descriptor for one epoch.
func (n *node) descriptor(epoch uint64) *pki.MixDescriptor {
	d := n.desc
	d.Epoch = epoch
	d.MixKeys = make(map[uint64][]byte)
	for e := epoch - epochSpan; e <= epoch+epochSpan; e++ {
		d.MixKeys[e] = n.mixPub
	}
	return &d
}

// authority signs the consensus documents.
type authority struct {
	pub  sign.PublicKey
	priv sign.PrivateKey

	geo      *geo.Geometry
	gateway  *node
	mixes    []*node
	service  *node
	replicas []*pki.ReplicaDescriptor

	mu     sync.Mutex
	signed map[uint64][]byte
}

func newAuthority(g *geo.Geometry) (*authority, error) {
	pub, priv, err := signScheme.GenerateKey()
	if err != nil {
		return nil, err
	}
	a := &authority{
		pub:    pub,
		priv:   priv,
		geo:    g,
		signed: make(map[uint64][]byte),
	}
	if a.gateway, err = newNode("gateway"); err != nil {
		return nil, err
	}
	a.gateway.desc.IsGatewayNode = true
	for i := range mixLayers {
		m, err := newNode(fmt.Sprintf("mix%d", i+1))
		if err != nil {
			return nil, err
		}
		a.mixes = append(a.mixes, m)
	}
	if a.service, err = newNode("servicenode"); err != nil {
		return nil, err
	}
	a.service.desc.IsServiceNode = true
	a.service.desc.Kaetzchen = make(map[string]map[string]interface{})
	a.service.desc.KaetzchenAdvertizedData = make(map[string]map[string]interface{})
	return a, nil
}

// nodes returns every node, keyed by identity hash.
func (a *authority) nodes() map[[32]byte]*node {
	m := map[[32]byte]*node{a.gateway.idHash: a.gateway, a.service.idHash: a.service}
	for _, n := range a.mixes {
		m[n.idHash] = n
	}
	return m
}

// document returns the consensus for an epoch, building it on first use.
// Every caller gets its own parse of the signed document, so no two
// components share one.
func (a *authority) document(epoch uint64) (*pki.Document, []byte, error) {
	signed, err := a.sign(epoch)
	if err != nil {
		return nil, nil, err
	}
	d, err := pki.ParseDocument(signed)
	if err != nil {
		return nil, nil, err
	}
	return d, signed, nil
}

func (a *authority) sign(epoch uint64) ([]byte, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if signed, ok := a.signed[epoch]; ok {
		return signed, nil
	}
	ids := make([]uint8, len(a.replicas))
	idKeys := make([][]byte, len(a.replicas))
	for i, r := range a.replicas {
		ids[i] = r.ReplicaID
		idKeys[i] = r.IdentityKey
	}
	topology := make([][]*pki.MixDescriptor, len(a.mixes))
	for i, m := range a.mixes {
		topology[i] = []*pki.MixDescriptor{m.descriptor(epoch)}
	}
	d := &pki.Document{
		Epoch:        epoch,
		GenesisEpoch: epoch - epochSpan,
		// Hops take about a millisecond and the gateway ignores their
		// delays. Send slots come every 10ms or so: with no network
		// latency a faster rate only multiplies the daemon's polls of the
		// courier while the replicas work.
		Mu:                            1,
		LambdaP:                       0.1,
		LambdaL:                       0.001,
		LambdaM:                       0.001,
		LambdaG:                       0.001,
		LambdaR:                       0.001,
		Topology:                      topology,
		GatewayNodes:                  []*pki.MixDescriptor{a.gateway.descriptor(epoch)},
		ServiceNodes:                  []*pki.MixDescriptor{a.service.descriptor(epoch)},
		StorageReplicas:               a.replicas,
		ConfiguredReplicaIDs:          ids,
		ConfiguredReplicaIdentityKeys: idKeys,
		SharedRandomValue:             make([]byte, 32),
		SphinxGeometryHash:            a.geo.Hash(),
		PKISignatureScheme:            signSchemeName,
	}
	// The document shares descriptors with every other epoch's, and
	// pki.SignDocument decodes the signed document back into what it is
	// given: sign its bytes instead.
	d.Version = pki.DocumentVersion
	certified, err := d.MarshalCertificate()
	if err != nil {
		return nil, err
	}
	signed, err := cert.SignMulti(a.priv, a.pub, certified)
	if err != nil {
		return nil, err
	}
	a.signed[epoch] = signed
	return signed, nil
}

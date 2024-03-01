// pkicache.go - Katzenpost server PKI document cache.
// Copyright (C) 2017  Yawning Angel.
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

// Package pkicache provides a rudimentary cached representation of a PKI
// Document suitable for server use.
package pkicache

import (
	"fmt"

	"github.com/katzenpost/hpqc/hash"
	"github.com/katzenpost/hpqc/sign"
	"github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/sphinx/constants"
)

// Entry is a cached PKI Document.
type Entry struct {
	doc      *pki.Document
	self     *pki.MixDescriptor
	incoming map[[constants.NodeIDLength]byte]*pki.MixDescriptor
	outgoing map[[constants.NodeIDLength]byte]*pki.MixDescriptor
	all      map[[constants.NodeIDLength]byte]*pki.MixDescriptor
}

// Epoch returns the epoch that the cached PKI document is valid for.
func (e *Entry) Epoch() uint64 {
	return e.doc.Epoch
}

// MixMaxDelay returns the MixMaxDelay for the cached PKI document.
func (e *Entry) MuMaxDelay() uint64 {
	return e.doc.MuMaxDelay
}

// SendRatePerMinute returns the SendRatePerMinute for the cached PKI document.
func (e *Entry) SendRatePerMinute() uint64 {
	return e.doc.SendRatePerMinute
}

// Self returns the descriptor for the current node.
func (e *Entry) Self() *pki.MixDescriptor {
	return e.self
}

// Document returns the PKI document backing the Entry.
func (e *Entry) Document() *pki.Document {
	return e.doc
}

// GetIncomingByID returns the MixDescriptor for a incoming connection source
// queried by node ID, or nil iff the node ID is not a valid source.
func (e *Entry) GetIncomingByID(id *[constants.NodeIDLength]byte) *pki.MixDescriptor {
	desc, ok := e.incoming[*id]
	if !ok {
		return nil
	}
	return desc
}

// GetOutgoingByID returns the MixDescriptor for an outgoing connection
// destination queried by node ID, or nil iff the node ID is not a valid
// destination.
func (e *Entry) GetOutgoingByID(id *[constants.NodeIDLength]byte) *pki.MixDescriptor {
	desc, ok := e.outgoing[*id]
	if !ok {
		return nil
	}
	return desc
}

// GetByID returns the MixDescriptor by node ID, or nil iff the node ID is not
// listed in the document.
func (e *Entry) GetByID(id *[constants.NodeIDLength]byte) *pki.MixDescriptor {
	desc, ok := e.all[*id]
	if !ok {
		return nil
	}
	return desc
}

// Outgoing returns a slice of all MixDescriptors that describe valid outgoing
// connection destinations.
func (e *Entry) Outgoing() []*pki.MixDescriptor {
	l := make([]*pki.MixDescriptor, 0, len(e.outgoing))
	for _, v := range e.outgoing {
		l = append(l, v)
	}
	return l
}

func (e *Entry) isOurLayerSane(isGateway, isServiceNode bool) bool {
	if isGateway && isServiceNode {
		return false
	}
	if isGateway && !e.self.IsGatewayNode {
		return false
	}
	if isServiceNode && !e.self.IsServiceNode {
		return false
	}
	if !isGateway {
		idHash := e.self.IdentityKey.Sum256()
		layer, err := e.doc.GetMixLayer(&idHash)
		if err != nil || layer == pki.LayerGateway {
			return false
		}
		if int(layer) >= len(e.doc.Topology) {
			return false
		}
	}
	if !isServiceNode {
		idHash := e.self.IdentityKey.Sum256()
		layer, err := e.doc.GetMixLayer(&idHash)
		if err != nil || layer == pki.LayerService {
			return false
		}
		if int(layer) >= len(e.doc.Topology) {
			return false
		}
	}
	return true
}

func (e *Entry) incomingLayer() uint8 {
	idHash := hash.Sum256(e.self.IdentityKey)
	layer, err := e.doc.GetMixLayer(&idHash)
	if err != nil {
		panic(err)
	}
	switch layer {
	case pki.LayerService:
		return uint8(len(e.doc.Topology)) - 1
	case 0:
		return pki.LayerGateway
	}
	return layer - 1
}

func (e *Entry) outgoingLayer() uint8 {
	idHash := hash.Sum256(e.self.IdentityKey)
	layer, err := e.doc.GetMixLayer(&idHash)
	if err != nil {
		panic(err)
	}
	switch int(layer) {
	case len(e.doc.Topology) - 1:
		return pki.LayerService
	case pki.LayerGateway:
		return 0
	}
	return layer + 1
}

// New constructs a new Entry from a given document.
func New(d *pki.Document, identityKey sign.PublicKey, isGateway, isServiceNode bool) (*Entry, error) {
	e := new(Entry)
	e.doc = d
	e.incoming = make(map[[constants.NodeIDLength]byte]*pki.MixDescriptor)
	e.outgoing = make(map[[constants.NodeIDLength]byte]*pki.MixDescriptor)
	e.all = make(map[[constants.NodeIDLength]byte]*pki.MixDescriptor)

	// Find our descriptor.
	var err error
	idKeyHash := hash.Sum256From(identityKey)
	e.self, err = d.GetNodeByKeyHash(&idKeyHash)
	if err != nil {
		return nil, err
	}

	// Ensure that the self descriptor has a sensible layer.
	if !e.isOurLayerSane(isGateway, isServiceNode) {
		layer, err := e.doc.GetMixLayer(&idKeyHash)
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("pkicache: self layer is invalid: %d", layer)
	}

	// Build the maps of peers that will connect to us, and that we will
	// connect to.
	appendMap := func(layer uint8, m map[[constants.NodeIDLength]byte]*pki.MixDescriptor) {
		var nodes []*pki.MixDescriptor
		switch layer {
		case pki.LayerGateway:
			nodes = e.doc.GatewayNodes
		case pki.LayerService:
			nodes = e.doc.ServiceNodes
		default:
			nodes = e.doc.Topology[layer]
		}
		for _, v := range nodes {
			// The concrete PKI implementation is responsible for ensuring
			// that documents only contain one descriptor per identity key.
			nodeID := hash.Sum256(v.IdentityKey)
			m[nodeID] = v
		}
	}
	appendMap(e.incomingLayer(), e.incoming)
	appendMap(e.outgoingLayer(), e.outgoing)

	// Build the list of all nodes.
	for i := 0; i < len(e.doc.Topology); i++ {
		appendMap(uint8(i), e.all)
	}
	appendMap(pki.LayerGateway, e.all)
	appendMap(pki.LayerService, e.all)
	return e, nil
}

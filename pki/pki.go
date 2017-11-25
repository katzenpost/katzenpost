// pki.go - Mixnet PKI interfaces
// Copyright (C) 2017  David Stainton, Yawning Angel.
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

// Package pki provides the mix network PKI related interfaces.
package pki

import (
	"bytes"
	"context"
	"fmt"

	"github.com/katzenpost/core/crypto/ecdh"
	"github.com/katzenpost/core/crypto/eddsa"
)

// LayerProvider is the Layer that providers list in their MixDescriptors.
const LayerProvider = 255

// Document is a PKI document.
type Document struct {
	// Epoch is the epoch for which this Document instance is valid for.
	Epoch uint64

	// Lambda is the inverse of the mean of the exponential distribution that
	// clients will use to sample delays.
	Lambda float64

	// MaxDelay is the maximum per-hop delay in milliseconds.
	MaxDelay uint64

	// Topology is the mix network topology, excluding providers.
	Topology [][]*MixDescriptor

	// Providers is the list of providers that can interact with the mix
	// network.
	Providers []*MixDescriptor
}

// String returns a string representation of a Document.
func (d *Document) String() string {
	stringifyDescSlice := func(nodes []*MixDescriptor) string {
		s := ""
		for idx, v := range nodes {
			s += fmt.Sprintf("%+v", v)
			if idx != len(nodes)-1 {
				s += ","
			}
		}
		return s
	}

	s := fmt.Sprintf("&{Epoch:%v Lambda:%v MaxDelay:%v Topology:", d.Epoch, d.Lambda, d.MaxDelay)
	for l, nodes := range d.Topology {
		s += fmt.Sprintf("[%v]{", l)
		s += stringifyDescSlice(nodes)
		if l != len(nodes)-1 {
			s += "},"
		}
	}

	s += "}, Providers:[]{"
	s += stringifyDescSlice(d.Providers)
	s += "}}"
	return s
}

// GetProvider returns the MixDescriptor for the given provider Name.
func (d *Document) GetProvider(name string) (*MixDescriptor, error) {
	for _, v := range d.Providers {
		if v.Name == name {
			return v, nil
		}
	}
	return nil, fmt.Errorf("pki: provider '%v' not found", name)
}

// GetProviderByKey returns the specific provider descriptor corresponding
// to the specified IdentityKey.
func (d *Document) GetProviderByKey(key []byte) (*MixDescriptor, error) {
	for _, v := range d.Providers {
		if v.IdentityKey == nil {
			return nil, fmt.Errorf("pki: document contains invalid descriptors")
		}
		if bytes.Equal(v.IdentityKey.Bytes(), key) {
			return v, nil
		}
	}
	return nil, fmt.Errorf("pki: provider not found")
}

// GetMix returns the MixDescriptor for the given mix Name.
func (d *Document) GetMix(name string) (*MixDescriptor, error) {
	for _, l := range d.Topology {
		for _, v := range l {
			if v.Name == name {
				return v, nil
			}
		}
	}
	return nil, fmt.Errorf("pki: mix '%v' not found", name)
}

// GetMixesInLayer returns all the mix descriptors for a given layer.
func (d *Document) GetMixesInLayer(layer uint8) ([]*MixDescriptor, error) {
	if len(d.Topology)-1 < int(layer) {
		return nil, fmt.Errorf("pki: invalid layer: '%v'", layer)
	}
	return d.Topology[layer], nil
}

// GetMixByKey returns the specific mix descriptor corresponding
// to the specified IdentityKey.
func (d *Document) GetMixByKey(key []byte) (*MixDescriptor, error) {
	for _, l := range d.Topology {
		for _, v := range l {
			if v.IdentityKey == nil {
				return nil, fmt.Errorf("pki: document contains invalid descriptors")
			}
			if bytes.Equal(v.IdentityKey.Bytes(), key) {
				return v, nil
			}
		}
	}
	return nil, fmt.Errorf("pki: mix not found")
}

// GetNode returns the specific descriptor corresponding to the specified
// node Name.
func (d *Document) GetNode(name string) (*MixDescriptor, error) {
	if m, err := d.GetMix(name); err == nil {
		return m, nil
	}
	if m, err := d.GetProvider(name); err == nil {
		return m, nil
	}
	return nil, fmt.Errorf("pki: node not found")
}

// GetNodeByKey returns the specific descriptor corresponding to the
// specified IdentityKey.
func (d *Document) GetNodeByKey(key []byte) (*MixDescriptor, error) {
	if m, err := d.GetMixByKey(key); err == nil {
		return m, nil
	}
	if m, err := d.GetProviderByKey(key); err == nil {
		return m, nil
	}
	return nil, fmt.Errorf("pki: node not found")
}

// MixDescriptor is a description of a given Mix or Provider (node).
type MixDescriptor struct {
	// Name is the human readable (descriptive) node identifier.
	Name string

	// IdentityKey is the node's identity (signing) key.
	IdentityKey *eddsa.PublicKey

	// LinkKey is the node's wire protocol public key.
	LinkKey *ecdh.PublicKey

	// MixKeys is a map of epochs to Sphinx keys.
	MixKeys map[uint64]*ecdh.PublicKey

	// Addresses is a list of address/port combinations that can be used to
	// reach the node.
	Addresses []string

	// Layer is the topology layer.
	Layer uint8

	// LoadWeight is the node's load balancing weight (unused).
	LoadWeight uint8
}

// Client is the abstract interface used for PKI interaction.
type Client interface {
	// Get returns the PKI document for the provided epoch.
	Get(ctx context.Context, epoch uint64) (*Document, error)

	// Post posts the node's descriptor to the PKI for the provided epoch.
	Post(ctx context.Context, epoch uint64, signingKey *eddsa.PrivateKey, d *MixDescriptor) error
}

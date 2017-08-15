// pki.go - Mixnet PKI interfaces
// Copyright (C) 2017  David Stainton.
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

// Package provider the mix network PKI client interface
package pki

import (
	"github.com/katzenpost/core/crypto/ecdh"
	"github.com/katzenpost/core/sphinx/constants"
)

type MixDescriptor struct {
	Name            string
	ID              [constants.NodeIDLength]byte
	IsProvider      bool
	LoadWeight      uint8
	TopologyLayer   uint8
	EpochAPublicKey *ecdh.PublicKey
	EpochBPublicKey *ecdh.PublicKey
	EpochCPublicKey *ecdh.PublicKey
	Ipv4Address     string
	TcpPort         int
}

// Client is the mixnet client PKI interface
// XXX david: so far this is messy and totally unfinished.
// we should look at all the requirements of all the places
// in the code where interaction with the PKI happens and
// make a proper API. Currently, I have completely skipped messing
// around with key updates as I am currently working on
// the client which is not concerned with such things.
type Client interface {
	// GetLatestConsensusMap returns a fresh mix network map
	// where the Node ID is the key and the descriptor the value
	GetLatestConsensusMap() *map[[constants.NodeIDLength]byte]*MixDescriptor

	// GetProviderDescriptor returns the MixDescriptor for the given Provider name
	GetProviderDescriptor(name string) (*MixDescriptor, error)

	// GetMixesInLayer returns all the mix descriptors for a given layer of mix network topology
	GetMixesInLayer(layer uint8) []*MixDescriptor

	// GetDescriptor returns the specific mix descriptor corresponding
	// to the given mix descriptor ID aka Node ID
	GetDescriptor(id [constants.NodeIDLength]byte) (*MixDescriptor, error)
}

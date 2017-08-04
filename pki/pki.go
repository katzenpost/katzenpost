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

package pki

import (
	"github.com/katzenpost/core/crypto/ecdh"
	"github.com/katzenpost/core/sphinx/constants"
)

type MixDescriptor struct {
	ID              [constants.NodeIDLength]byte
	TopologyLayer   uint8
	EpochAPublicKey *ecdh.PublicKey
	EpochBPublicKey *ecdh.PublicKey
	EpochCPublicKey *ecdh.PublicKey
}

type Mix interface {
	GetLatestConsensusMap() map[[constants.NodeIDLength]byte]*MixDescriptor
}

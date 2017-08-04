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
	"encoding/json"
	"io/ioutil"

	"github.com/katzenpost/core/crypto/ecdh"
	"github.com/katzenpost/core/sphinx/constants"
)

type MixDescriptor struct {
	ID                  [constants.NodeIDLength]byte
	LoadWeight          uint8
	EpochATopologyLayer uint8
	EpochBTopologyLayer uint8
	EpochCTopologyLayer uint8
	EpochAPublicKey     *ecdh.PublicKey
	EpochBPublicKey     *ecdh.PublicKey
	EpochCPublicKey     *ecdh.PublicKey
}

type ConsensusList struct {
	list []MixDescriptor
}

type ConsensusMap map[[constants.NodeIDLength]byte]*MixDescriptor

type Mix interface {
	GetLatestConsensusMap() *ConsensusMap
}

type StaticConsensus struct {
	consensusMap ConsensusMap
}

func ConsensusFromFile(filePath string) (*StaticConsensus, error) {
	fileData, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	consensus := new(ConsensusList)
	err = json.Unmarshal(fileData, &consensus)
	if err != nil {
		return nil, err
	}
	m := make(ConsensusMap)
	for i := 0; i < len(consensus.list); i++ {
		m[consensus.list[i].ID] = &consensus.list[i]
	}
	j := StaticConsensus{
		consensusMap: m,
	}
	return &j, nil
}

func (t *StaticConsensus) GetLatestConsensusMap() *ConsensusMap {
	return &t.consensusMap
}

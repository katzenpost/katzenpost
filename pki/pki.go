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
	"encoding/base64"
	"encoding/json"
	"io/ioutil"

	"github.com/katzenpost/core/crypto/ecdh"
	"github.com/katzenpost/core/sphinx/constants"
)

type MixDescriptor struct {
	Nickname            string
	ID                  [constants.NodeIDLength]byte
	LoadWeight          uint8
	EpochATopologyLayer uint8
	EpochBTopologyLayer uint8
	EpochCTopologyLayer uint8
	EpochAPublicKey     *ecdh.PublicKey
	EpochBPublicKey     *ecdh.PublicKey
	EpochCPublicKey     *ecdh.PublicKey
	Ipv4Address         string
	TcpPort             int
}

type JsonMixDescriptor struct {
	Nickname            string
	ID                  string
	LoadWeight          int
	EpochATopologyLayer int
	EpochBTopologyLayer int
	EpochCTopologyLayer int
	EpochAPublicKey     string
	EpochBPublicKey     string
	EpochCPublicKey     string
	Ipv4Address         string
	TcpPort             int
}

type ConsensusList struct {
	List []MixDescriptor
}

func (m *MixDescriptor) JsonMixDescriptor() *JsonMixDescriptor {
	j := JsonMixDescriptor{
		Nickname:            m.Nickname,
		ID:                  base64.StdEncoding.EncodeToString(m.ID[:]),
		LoadWeight:          int(m.LoadWeight),
		EpochATopologyLayer: int(m.EpochATopologyLayer),
		EpochBTopologyLayer: int(m.EpochBTopologyLayer),
		EpochCTopologyLayer: int(m.EpochCTopologyLayer),
		EpochAPublicKey:     base64.StdEncoding.EncodeToString(m.EpochAPublicKey.Bytes()),
		//EpochBPublicKey:     base64.StdEncoding.EncodeToString(m.EpochBPublicKey.Bytes()),
		//EpochCPublicKey:     base64.StdEncoding.EncodeToString(m.EpochCPublicKey.Bytes()),
		Ipv4Address: m.Ipv4Address,
		TcpPort:     m.TcpPort,
	}
	return &j
}

type ConsensusMap map[[constants.NodeIDLength]byte]*MixDescriptor
type JsonConsensusMap map[[constants.NodeIDLength]byte]*JsonMixDescriptor

type JsonConsensus struct {
	Descriptors []JsonMixDescriptor
}

type Mix interface {
	GetLatestConsensusMap() *ConsensusMap
}

type StaticConsensus struct {
	consensusMap ConsensusMap
}

func (t *StaticConsensus) GetLatestConsensusMap() *ConsensusMap {
	return &t.consensusMap
}

func StaticConsensusFromFile(filePath string) (*StaticConsensus, error) {
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
	for i := 0; i < len(consensus.List); i++ {
		m[consensus.List[i].ID] = &consensus.List[i]
	}
	j := StaticConsensus{
		consensusMap: m,
	}
	return &j, nil
}

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
	"fmt"
	"io/ioutil"
	"strings"

	"github.com/katzenpost/core/crypto/ecdh"
	"github.com/katzenpost/core/sphinx/constants"
	"github.com/op/go-logging"
)

var log = logging.MustGetLogger("mixclient")

type ProviderDescriptor struct {
	Name              string
	LongtermPublicKey *ecdh.PublicKey
	Ipv4Address       string
	TcpPort           int
}

type JsonProviderDescriptor struct {
	Name              string
	LongtermPublicKey string
	Ipv4Address       string
	TcpPort           int
}

func (d *ProviderDescriptor) JsonProviderDescriptor() *JsonProviderDescriptor {
	desc := JsonProviderDescriptor{
		Name:              strings.ToLower(d.Name),
		LongtermPublicKey: base64.StdEncoding.EncodeToString(d.LongtermPublicKey.Bytes()),
		Ipv4Address:       d.Ipv4Address,
		TcpPort:           d.TcpPort,
	}
	return &desc
}

func (j *JsonProviderDescriptor) ProviderDescriptor() (*ProviderDescriptor, error) {
	key := ecdh.PublicKey{}
	rawKey, err := base64.StdEncoding.DecodeString(j.LongtermPublicKey)
	if err != nil {
		return nil, err
	}
	err = key.FromBytes(rawKey)
	if err != nil {
		return nil, err
	}
	desc := ProviderDescriptor{
		Name:              j.Name,
		LongtermPublicKey: &key,
		Ipv4Address:       j.Ipv4Address,
		TcpPort:           j.TcpPort,
	}
	return &desc, nil
}

type MixDescriptor struct {
	Nickname        string
	ID              [constants.NodeIDLength]byte
	LoadWeight      uint8
	TopologyLayer   uint8
	EpochAPublicKey *ecdh.PublicKey
	Ipv4Address     string
	TcpPort         int
}

type JsonMixDescriptor struct {
	Nickname        string
	ID              string
	LoadWeight      int
	TopologyLayer   int
	EpochAPublicKey string
	Ipv4Address     string
	TcpPort         int
}

func (m *MixDescriptor) JsonMixDescriptor() *JsonMixDescriptor {
	desc := JsonMixDescriptor{
		Nickname:        m.Nickname,
		ID:              base64.StdEncoding.EncodeToString(m.ID[:]),
		LoadWeight:      int(m.LoadWeight),
		TopologyLayer:   int(m.TopologyLayer),
		EpochAPublicKey: base64.StdEncoding.EncodeToString(m.EpochAPublicKey.Bytes()),
		Ipv4Address:     m.Ipv4Address,
		TcpPort:         m.TcpPort,
	}
	return &desc
}

func (j *JsonMixDescriptor) MixDescriptor() (*MixDescriptor, error) {
	idBytes, err := base64.StdEncoding.DecodeString(j.ID)
	if err != nil {
		return nil, err
	}
	var id [constants.NodeIDLength]byte
	copy(id[:], idBytes)
	aBytes, err := base64.StdEncoding.DecodeString(j.EpochAPublicKey)
	if err != nil {
		return nil, err
	}
	keyA := ecdh.PublicKey{}
	keyA.FromBytes(aBytes)
	d := MixDescriptor{
		Nickname:        strings.ToLower(j.Nickname),
		ID:              id,
		LoadWeight:      uint8(j.LoadWeight),
		TopologyLayer:   uint8(j.TopologyLayer),
		EpochAPublicKey: &keyA,
		Ipv4Address:     j.Ipv4Address,
		TcpPort:         j.TcpPort,
	}
	return &d, nil
}

type JsonStaticPKI struct {
	MixDescriptors      []JsonMixDescriptor
	ProviderDescriptors []JsonProviderDescriptor
}

// Client is the mixnet client PKI interface
type Client interface {
	GetLatestConsensusMap() *map[[constants.NodeIDLength]byte]*MixDescriptor
	GetProviderDescriptor(name string) (*ProviderDescriptor, error)
}

type StaticPKI struct {
	mixMap      map[[constants.NodeIDLength]byte]*MixDescriptor
	providerMap map[string]*ProviderDescriptor
}

func (t *StaticPKI) GetLatestConsensusMap() *map[[constants.NodeIDLength]byte]*MixDescriptor {
	return &t.mixMap
}

func (t *StaticPKI) GetProviderDescriptor(name string) (*ProviderDescriptor, error) {
	log.Debugf("GET PROVIDER DESCRIPTOR: %s", name)
	v, ok := t.providerMap[strings.ToLower(name)]
	if !ok {
		return nil, fmt.Errorf("provider descriptor name not found: %s", name)
	}
	return v, nil
}

func StaticPKIFromFile(filePath string) (*StaticPKI, error) {
	fileData, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, err
	}
	jsonPKI := JsonStaticPKI{}
	err = json.Unmarshal(fileData, &jsonPKI)
	if err != nil {
		return nil, err
	}
	providerMap := make(map[string]*ProviderDescriptor)
	mixMap := make(map[[constants.NodeIDLength]byte]*MixDescriptor)

	for _, providerDesc := range jsonPKI.ProviderDescriptors {
		log.Debugf("mix pki: provider %s", providerDesc.Name)
		providerMap[strings.ToLower(providerDesc.Name)], err = providerDesc.ProviderDescriptor()
		if err != nil {
			return nil, err
		}
	}

	for _, mixDesc := range jsonPKI.MixDescriptors {
		idBytes, err := base64.StdEncoding.DecodeString(mixDesc.ID)
		if err != nil {
			return nil, err
		}
		var id [constants.NodeIDLength]byte
		copy(id[:], idBytes)
		mixMap[id], err = mixDesc.MixDescriptor()
		if err != nil {
			return nil, err
		}
	}

	staticPKI := StaticPKI{
		mixMap:      mixMap,
		providerMap: providerMap,
	}
	return &staticPKI, nil
}

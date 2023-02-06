// client.go - map service client
// Copyright (C) 2021  Masala
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

package client

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"github.com/fxamacker/cbor/v2"
	"github.com/katzenpost/katzenpost/client"
	"github.com/katzenpost/katzenpost/client/utils"
	"github.com/katzenpost/katzenpost/core/sphinx"
	"github.com/katzenpost/katzenpost/map/common"
	"sort"
)


var (
	PayloadSize int
	ErrStatusNotFound = errors.New("StatusNotFound")
)

type Client struct {
	Session *client.Session
}

type StorageLocation interface {
	Secret() common.MessageID
	TID() common.MessageID
	Name() string
	Provider() string
}

type mapStorage struct {
	secret         common.MessageID
	tid            common.MessageID
	name, provider string
}

func (m *mapStorage) Secret() common.MessageID {
	return m.secret
}
func (m *mapStorage) TID() common.MessageID {
	return m.tid
}
func (m *mapStorage) Name() string {
	return m.name
}
func (m *mapStorage) Provider() string {
	return m.provider
}

type DeterministicDescriptorList []utils.ServiceDescriptor

func (d DeterministicDescriptorList) Less(i, j int) bool {
	return d[i].Name+d[i].Provider < d[j].Name+d[j].Provider
}
func (d DeterministicDescriptorList) Len() int {
	return len(d)
}
func (d DeterministicDescriptorList) Swap(i, j int) {
	d[i], d[j] = d[j], d[i]
}

func deterministicSelect(descs []utils.ServiceDescriptor, slot int) utils.ServiceDescriptor {
	// TODO: order the descriptors by their identity keys
	ddescs := DeterministicDescriptorList(descs)
	sort.Sort(ddescs)
	return ddescs[slot]
}

// GetStorageProvider returns the deterministically selected storage provider given a storage secret ID
func (c *Client) GetStorageProvider(ID common.MessageID) (StorageLocation, error) {
	// doc must be current document!
	doc := c.Session.CurrentDocument()
	if doc == nil {
		return nil, errors.New("No PKI document") // XXX: find correct error
	}
	descs := utils.FindServices(common.MapServiceName, doc)
	if len(descs) == 0 {
		return nil, errors.New("No descriptors")
	}
	// hash ID with the PriorSharedRandom value or other consensus parameters
	temporalStorageId := sha256.New()
	// XXX: consider what happens at epoch transitions
	temporalStorageId.Write(doc.PriorSharedRandom[0])
	temporalStorageId.Write(ID[:])
	var tid common.MessageID
	copy(tid[:], temporalStorageId.Sum(nil))
	slot := int(binary.LittleEndian.Uint64(tid[:8])) % len(descs)
	// sort the descs and return the chosen one
	desc := deterministicSelect(descs, slot)
	return &mapStorage{name: desc.Name, provider: desc.Provider, secret: ID, tid: tid}, nil
}

// Put places a value into the store
func (c *Client) Put(ID common.MessageID, payload []byte) error {
	loc, err := c.GetStorageProvider(ID)
	if err != nil {
		return err
	}
	b := common.MapRequest{TID: loc.TID(), Payload: payload}
	// XXX: ideally we limit the number of retries
	// so that it doesn't keep trying to deliver to a stale/missing service forever...
	serialized, err := cbor.Marshal(b)
	if err != nil {
		return err
	}

	_, err = c.Session.SendReliableMessage(loc.Name(), loc.Provider(), serialized)
	// XXX: do we need to track msgId and see if it was delivered or not ???
	return err
}

// Get requests ID from the chosen storage node and returns a payload or error
func (c *Client) Get(ID common.MessageID) ([]byte, error) {
	loc, err := c.GetStorageProvider(ID)
	if err != nil {
		return nil, err
	}
	b := &common.MapRequest{TID: loc.TID()}
	serialized, err := cbor.Marshal(b)
	if err != nil {
		return nil, err
	}

	r, err := c.Session.BlockingSendUnreliableMessage(loc.Name(), loc.Provider(), serialized)
	if err != nil {
		return nil, err
	}
	// unwrap the response and return the payload
	resp := &common.MapResponse{}
	err = cbor.Unmarshal(r, resp)
	if err != nil {
		return nil, err
	}
	if resp.Status == common.StatusNotFound {
		return nil, ErrStatusNotFound
	}
	return resp.Payload, nil
}

func NewClient(session *client.Session) (*Client, error) {
	return &Client{Session: session}, nil
}

func init() {
	b, _ := cbor.Marshal(common.MapRequest{})
	cborFrameOverhead := len(b)
	geo := sphinx.DefaultGeometry()
	wtfFactor := 4 // XXX: command Overhead ???
	PayloadSize = geo.UserForwardPayloadLength - cborFrameOverhead - wtfFactor
}

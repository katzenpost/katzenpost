// client.go - pigeonhole service client
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
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"sort"

	"github.com/fxamacker/cbor/v2"
	"github.com/katzenpost/hpqc/sign/ed25519"
	"github.com/katzenpost/katzenpost/client"
	"github.com/katzenpost/katzenpost/client/utils"
	"github.com/katzenpost/katzenpost/pigeonhole/common"
	"golang.org/x/crypto/hkdf"
)

var (
	cborFrameOverhead = 0 // overhead is determined by init()
	hash              = sha256.New
)

type Client struct {
	Session *client.Session
}

func NewClient(s *client.Session) (*Client, error) {
	return &Client{Session: s}, nil
}

type StorageLocation interface {
	ID() common.MessageID
	Name() string
	Provider() string
}

type pigeonHoleStorage struct {
	id             common.MessageID
	name, provider string
}

func (m *pigeonHoleStorage) ID() common.MessageID {
	return m.id
}
func (m *pigeonHoleStorage) Name() string {
	return m.name
}
func (m *pigeonHoleStorage) Provider() string {
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
	descs := utils.FindServices(common.PigeonHoleServiceName, doc)
	if len(descs) == 0 {
		return nil, errors.New("No descriptors")
	}
	slot := int(binary.LittleEndian.Uint64(ID[:8])) % len(descs)
	// sort the descs and return the chosen one
	desc := deterministicSelect(descs, slot)
	return &pigeonHoleStorage{name: desc.Name, provider: desc.Provider, id: ID}, nil
}

// Put places a value into the store
func (c *Client) Put(ctx context.Context, ID common.MessageID, signature, payload []byte) error {
	loc, err := c.GetStorageProvider(ID)
	if err != nil {
		return err
	}
	b := common.PigeonHoleRequest{ID: ID, Signature: signature, Payload: payload}
	serialized, err := cbor.Marshal(b)
	if err != nil {
		return err
	}

	r, err := c.Session.BlockingSendUnreliableMessageWithContext(ctx, loc.Name(), loc.Provider(), serialized)
	if err != nil {
		return err
	}
	resp := &common.PigeonHoleResponse{}
	_, err = cbor.UnmarshalFirst(r, resp)
	if err != nil {
		return err
	}
	if resp.Status == common.StatusOK {
		return nil
	} else {
		return common.ErrStatusFailed
	}
}

// PayloadSize returns the size of the user payload
func (c *Client) PayloadSize() int {
	geo := c.Session.SphinxGeometry()
	return geo.UserForwardPayloadLength - cborFrameOverhead - ed25519.SignatureSize
}

// Get requests ID from the chosen storage node and blocks until a response is received or is cancelled.
func (c *Client) Get(ctx context.Context, ID common.MessageID) ([]byte, error) {
	loc, err := c.GetStorageProvider(ID)
	if err != nil {
		return nil, err
	}
	b := &common.PigeonHoleRequest{ID: ID}
	serialized, err := cbor.Marshal(b)
	if err != nil {
		return nil, err
	}

	r, err := c.Session.BlockingSendUnreliableMessageWithContext(ctx, loc.Name(), loc.Provider(), serialized)
	if err != nil {
		return nil, err
	}
	// unwrap the response and return the payload
	resp := &common.PigeonHoleResponse{}
	_, err = cbor.UnmarshalFirst(r, resp)
	if err != nil {
		return nil, err
	}
	if resp.Status == common.StatusNotFound {
		return nil, common.ErrStatusNotFound
	}
	return resp.Payload, nil
}

func init() {
	b, _ := cbor.Marshal(common.PigeonHoleRequest{})
	cborFrameOverhead = len(b)
}

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
	"github.com/katzenpost/katzenpost/core/crypto/eddsa"
	"github.com/katzenpost/katzenpost/core/sphinx"
	"github.com/katzenpost/katzenpost/map/common"
	"golang.org/x/crypto/hkdf"
	"sort"
)

var (
	PayloadSize       int
	hash              = sha256.New
	ErrStatusNotFound = errors.New("StatusNotFound")
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

type mapStorage struct {
	id             common.MessageID
	name, provider string
}

func (m *mapStorage) ID() common.MessageID {
	return m.id
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
	slot := int(binary.LittleEndian.Uint64(ID[:8])) % len(descs)
	// sort the descs and return the chosen one
	desc := deterministicSelect(descs, slot)
	return &mapStorage{name: desc.Name, provider: desc.Provider, id: ID}, nil
}

// Put places a value into the store
func (c *Client) Put(ID common.MessageID, signature, payload []byte) error {
	if !ID.WritePk().Verify(signature, payload) {
		return errors.New("signature does not verify Write")
	}

	loc, err := c.GetStorageProvider(ID)
	if err != nil {
		return err
	}
	b := common.MapRequest{ID: ID, Signature: signature, Payload: payload}
	// XXX: ideally we limit the number of retries
	// so that it doesn't keep trying to deliver to a stale/missing service forever...
	serialized, err := cbor.Marshal(b)
	if err != nil {
		return err
	}

	_, err = c.Session.SendUnreliableMessage(loc.Name(), loc.Provider(), serialized)
	// XXX: do we need to track msgId and see if it was delivered or not ???
	return err
}

// Get requests ID from the chosen storage node and returns a payload or error
func (c *Client) Get(ID common.MessageID, signature []byte) ([]byte, error) {

	if !ID.ReadPk().Verify(signature, ID[:]) {
		return nil, errors.New("signature does not verify Read")
	}
	loc, err := c.GetStorageProvider(ID)
	if err != nil {
		return nil, err
	}
	b := &common.MapRequest{ID: ID, Signature: signature}
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

// RWClient has both Get and Put
type RWClient interface {
	Put(addr []byte, payload []byte) error
	Get(addr []byte) ([]byte, error)
}

// ROClient only has Get
type ROClient interface {
	Get(addr []byte) ([]byte, error)
}

// WOClient only has Put
type WOClient interface {
	Put(addr []byte, payload []byte) error
}

// rwMap implements ReadWriteTranport using a ReadWriteCap and reference to map client
// The idea is that several streams can share map/client and client/session but
// have different capabilities for the underlying Streams transported by map/client
type rwMap struct {
	c     *Client
	rwCap common.ReadWriteCap
}

// Get implements RWClient.Get
func (r *rwMap) Get(addr []byte) ([]byte, error) {
	i := r.rwCap.Addr(addr)
	k := r.rwCap.Read(addr)
	return r.c.Get(i, k.Sign(i.Bytes()))
}

// Put implements RWClient.Put
func (r *rwMap) Put(addr []byte, payload []byte) error {
	i := r.rwCap.Addr(addr)
	k := r.rwCap.Read(addr)
	return r.c.Put(i, k.Sign(payload), payload)
}

// roMap implements ReadOnlyTranport using a ReadOnlyCap and reference to map client
type roMap struct {
	c     *Client
	roCap common.ReadOnlyCap
}

// Get implements ROClient.Get
func (r *roMap) Get(addr []byte) ([]byte, error) {
	i := r.roCap.Addr(addr)
	k := r.roCap.Read(addr)
	return r.c.Get(i, k.Sign(i.Bytes()))
}

// woMap implements WOClient
type woMap struct {
	c     *Client
	woCap common.WriteOnlyCap
}

// Put implements WOClient.Put
func (w *woMap) Put(addr []byte, payload []byte) error {
	i := w.woCap.Addr(addr)
	k := w.woCap.Write(addr)
	return w.c.Put(i, k.Sign(payload), payload)
}

// ReadWrite returns a Transport using map that can read or write with Get() and Put()
func ReadWrite(c *Client, rwCap common.ReadWriteCap) RWClient {
	m := new(rwMap)
	m.c = c
	m.rwCap = rwCap
	return m
}

// ReadOnly returns a Transport using map that can read with Get() only
func ReadOnly(c *Client, roCap common.ReadOnlyCap) ROClient {
	m := new(roMap)
	m.c = c
	m.roCap = roCap
	return m
}

// WriteOnly returns a Transport using map that can write with Put() only
func WriteOnly(c *Client, woCap common.WriteOnlyCap) WOClient {
	m := new(woMap)
	m.c = c
	m.woCap = woCap
	return m
}

// create a duplex using a shared secret
func DuplexFromSeed(c *Client, initiator bool, secret []byte) RWClient {
	salt := []byte("duplex initialized from seed is not for multi-party use")
	keymaterial := hkdf.New(hash, secret, salt, nil)
	var err error
	var pk1, pk2 *eddsa.PrivateKey
	// return the listener or dialer side of caps from seed
	if initiator {
		if pk1, err = eddsa.NewKeypair(keymaterial); err != nil {
			panic(err)
		}
		if pk2, err = eddsa.NewKeypair(keymaterial); err != nil {
			panic(err)
		}
	} else {
		if pk2, err = eddsa.NewKeypair(keymaterial); err != nil {
			panic(err)
		}
		if pk1, err = eddsa.NewKeypair(keymaterial); err != nil {
			panic(err)
		}
	}

	// initialize root capabilities for both keys
	rw1 := common.NewRWCap(pk1)
	rw2 := common.NewRWCap(pk2)

	// initiator socket
	return Duplex(c, rw1.ReadOnly(), rw2.WriteOnly())
}

// duplex holds a pair of ROClient and WOClient and implements
// RWClient with different read/write root capabilities so that a pair
// of clients may use the capabilities to communicate unidirectionally
type duplex struct {
	ro ROClient // used to read data to client
	wo WOClient // used to send data to peer
}

// Put implements RWClient.Put
func (s *duplex) Put(addr []byte, payload []byte) error {
	return s.wo.Put(addr, payload)
}

// Put implements RWClient.Get
func (s *duplex) Get(addr []byte) ([]byte, error) {
	return s.ro.Get(addr)
}

// Duplex returns a RWclient from a pair of ReadOnly and WriteOnly capabilities
func Duplex(c *Client, r common.ReadOnlyCap, w common.WriteOnlyCap) RWClient {
	s := new(duplex)
	s.wo = WriteOnly(c, w)
	s.ro = ReadOnly(c, r)
	return s
}

func init() {
	b, _ := cbor.Marshal(common.MapRequest{})
	cborFrameOverhead := len(b)
	geo := sphinx.DefaultGeometry()
	PayloadSize = geo.UserForwardPayloadLength - cborFrameOverhead - eddsa.SignatureSize
}

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
func (c *Client) Put(ID common.MessageID, signature, payload []byte) error {
	loc, err := c.GetStorageProvider(ID)
	if err != nil {
		return err
	}
	b := common.PigeonHoleRequest{ID: ID, Signature: signature, Payload: payload}
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

// PayloadSize returns the size of the user payload
func (c *Client) PayloadSize() int {
	geo := c.Session.SphinxGeometry()
	return geo.UserForwardPayloadLength - cborFrameOverhead - ed25519.SignatureSize
}

// Get requests ID from the chosen storage node and returns a payload or error
func (c *Client) Get(ID common.MessageID, signature []byte) ([]byte, error) {
	loc, err := c.GetStorageProvider(ID)
	if err != nil {
		return nil, err
	}
	b := &common.PigeonHoleRequest{ID: ID, Signature: signature}
	serialized, err := cbor.Marshal(b)
	if err != nil {
		return nil, err
	}

	ctx := context.Background()
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
		return nil, ErrStatusNotFound
	}
	return resp.Payload, nil
}

// ReadWriteClient has both Get and Put
type ReadWriteClient interface {
	Put(addr []byte, payload []byte) error
	Get(addr []byte) ([]byte, error)
	PayloadSize() int
}

// ReadOnlyClient only has Get
type ReadOnlyClient interface {
	Get(addr []byte) ([]byte, error)
	PayloadSize() int
}

// WriteOnlyClient only has Put
type WriteOnlyClient interface {
	Put(addr []byte, payload []byte) error
	PayloadSize() int
}

// rwPigeonHole implements ReadWriteTranport using a ReadWriteCap and reference to pigeonHole client
// The idea is that several streams can share pigeonHole/client and client/session but
// have different capabilities for the underlying Streams transported by pigeonHole/client
type rwPigeonHole struct {
	c     *Client
	rwCap common.ReadWriteCap
}

// Get implements ReadWriteClient.Get
func (r *rwPigeonHole) Get(addr []byte) ([]byte, error) {
	i := r.rwCap.Addr(addr)
	k := r.rwCap.ReadKey(addr)
	return r.c.Get(i, k.Sign(i.Bytes()))
}

// Put implements ReadWriteClient.Put
func (r *rwPigeonHole) Put(addr []byte, payload []byte) error {
	i := r.rwCap.Addr(addr)
	k := r.rwCap.ReadKey(addr)
	return r.c.Put(i, k.Sign(payload), payload)
}

// PayloadSize implements ReadWriteClient.PayloadSize
func (r *rwPigeonHole) PayloadSize() int {
	return r.c.PayloadSize()
}

// roPigeonHole implements ReadOnlyTranport using a ReadOnlyCap and reference to pigeonHole client
type roPigeonHole struct {
	c     *Client
	roCap common.ReadOnlyCap
}

// Get implements ReadOnlyClient.Get
func (r *roPigeonHole) Get(addr []byte) ([]byte, error) {
	i := r.roCap.Addr(addr)
	k := r.roCap.ReadKey(addr)
	return r.c.Get(i, k.Sign(i.Bytes()))
}

// PayloadSize implements ReadOnlyClient.PayloadSize
func (r *roPigeonHole) PayloadSize() int {
	return r.c.PayloadSize()
}

// woPigeonHole implements WriteOnlyClient
type woPigeonHole struct {
	c     *Client
	woCap common.WriteOnlyCap
}

// Put implements WriteOnlyClient.Put
func (w *woPigeonHole) Put(addr []byte, payload []byte) error {
	i := w.woCap.Addr(addr)
	k := w.woCap.WriteKey(addr)
	return w.c.Put(i, k.Sign(payload), payload)
}

// PayloadSize implements WriteOnlyClient.PayloadSize
func (r *woPigeonHole) PayloadSize() int {
	return r.c.PayloadSize()
}

// ReadWrite returns a Transport using pigeonHole that can read or write with Get() and Put()
func ReadWrite(c *Client, rwCap common.ReadWriteCap) ReadWriteClient {
	m := new(rwPigeonHole)
	m.c = c
	m.rwCap = rwCap
	return m
}

// ReadOnly returns a Transport using pigeonHole that can read with Get() only
func ReadOnly(c *Client, roCap common.ReadOnlyCap) ReadOnlyClient {
	m := new(roPigeonHole)
	m.c = c
	m.roCap = roCap
	return m
}

// WriteOnly returns a Transport using pigeonHole that can write with Put() only
func WriteOnly(c *Client, woCap common.WriteOnlyCap) WriteOnlyClient {
	m := new(woPigeonHole)
	m.c = c
	m.woCap = woCap
	return m
}

// create a duplex using a shared secret
func duplexCapsFromSeed(initiator bool, secret []byte) (*common.ROCap, *common.WOCap) {
	salt := []byte("duplex initialized from seed is not for multi-party use")
	keymaterial := hkdf.New(hash, secret, salt, nil)
	var err error
	var pk1, pk2 *ed25519.PrivateKey
	// return the listener or dialer side of caps from seed
	if initiator {
		if pk1, _, err = ed25519.NewKeypair(keymaterial); err != nil {
			panic(err)
		}
		if pk2, _, err = ed25519.NewKeypair(keymaterial); err != nil {
			panic(err)
		}
	} else {
		if pk2, _, err = ed25519.NewKeypair(keymaterial); err != nil {
			panic(err)
		}
		if pk1, _, err = ed25519.NewKeypair(keymaterial); err != nil {
			panic(err)
		}
	}

	// initialize root capabilities for both keys
	rw1 := common.NewRWCap(pk1)
	rw2 := common.NewRWCap(pk2)

	// return reader and writer
	return rw1.ReadOnly(), rw2.WriteOnly()
}

func DuplexFromSeed(c *Client, initiator bool, secret []byte) ReadWriteClient {
	ro, wo := duplexCapsFromSeed(initiator, secret)

	return Duplex(c, ro, wo)
}

// duplex holds a pair of ReadOnlyClient and WriteOnlyClient and implements
// ReadWriteClient with different read/write root capabilities so that a pair
// of clients may use the capabilities to communicate unidirectionally
type duplex struct {
	ro ReadOnlyClient  // used to read data to client
	wo WriteOnlyClient // used to send data to peer
}

// Put implements ReadWriteClient.Put
func (s *duplex) Put(addr []byte, payload []byte) error {
	return s.wo.Put(addr, payload)
}

// Put implements ReadWriteClient.Get
func (s *duplex) Get(addr []byte) ([]byte, error) {
	return s.ro.Get(addr)
}

// PayloadSize implements ReadWriteClient.PayloadSize
func (s *duplex) PayloadSize() int {
	return s.ro.PayloadSize()
}

// Duplex returns a RWclient from a pair of ReadOnly and WriteOnly capabilities
func Duplex(c *Client, r common.ReadOnlyCap, w common.WriteOnlyCap) ReadWriteClient {
	s := new(duplex)
	s.wo = WriteOnly(c, w)
	s.ro = ReadOnly(c, r)
	return s
}

func init() {
	b, _ := cbor.Marshal(common.PigeonHoleRequest{})
	cborFrameOverhead = len(b)
}

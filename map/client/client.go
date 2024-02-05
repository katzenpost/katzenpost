// SPDX-FileCopyrightText: Copyright (C) 2021  Masala
// SPDX-License-Identifier: AGPL-3.0-only

package client

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"sort"

	"github.com/fxamacker/cbor/v2"

	"github.com/katzenpost/katzenpost/client"
	"github.com/katzenpost/katzenpost/client/utils"
	"github.com/katzenpost/katzenpost/core/crypto/eddsa"
	"github.com/katzenpost/katzenpost/map/crypto"
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
	ID() *crypto.MessageID
	Name() string
	Provider() string
}

type mapStorage struct {
	id       *crypto.MessageID
	name     string
	provider string
}

func (m *mapStorage) ID() *crypto.MessageID {
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
func (c *Client) GetStorageProvider(id *crypto.MessageID) (StorageLocation, error) {
	// doc must be current document!
	doc := c.Session.CurrentDocument()
	if doc == nil {
		return nil, errors.New("No PKI document") // XXX: find correct error
	}
	descs := utils.FindServices(crypto.MapServiceName, doc)
	if len(descs) == 0 {
		return nil, errors.New("No descriptors")
	}
	slot := int(binary.LittleEndian.Uint64(id[:8])) % len(descs)
	// sort the descs and return the chosen one
	desc := deterministicSelect(descs, slot)
	return &mapStorage{
		name:     desc.Name,
		provider: desc.Provider,
		id:       id,
	}, nil
}

// Put places a value into the store
func (c *Client) Put(cap *crypto.WriteCapability) error {
	loc, err := c.GetStorageProvider(cap.ID)
	if err != nil {
		return err
	}
	b := &crypto.MapRequest{
		ID:        cap.ID,
		Signature: cap.Signature,
		Payload:   cap.Payload,
	}
	// XXX: ideally we limit the number of retries
	// so that it doesn't keep trying to deliver to a stale/missing service forever...
	serialized, err := cbor.Marshal(b)
	if err != nil {
		return err
	}

	fmt.Printf("putting blob into storage: %x\n", serialized)

	_, err = c.Session.SendUnreliableMessage(loc.Name(), loc.Provider(), serialized)
	// XXX: do we need to track msgId and see if it was delivered or not ???
	return err
}

// PayloadSize returns the size of the user payload
func (c *Client) PayloadSize() int {
	geo := c.Session.SphinxGeometry()
	return geo.UserForwardPayloadLength - cborFrameOverhead - eddsa.SignatureSize
}

// Get requests ID from the chosen storage node and returns a payload or error
func (c *Client) Get(cap *crypto.ReadCapability) ([]byte, error) {
	loc, err := c.GetStorageProvider(cap.ID)
	if err != nil {
		return nil, err
	}
	b := &crypto.MapRequest{
		ID:        cap.ID,
		Signature: cap.Signature,
	}
	serialized, err := cbor.Marshal(b)
	if err != nil {
		return nil, err
	}

	r, err := c.Session.BlockingSendUnreliableMessage(loc.Name(), loc.Provider(), serialized)
	if err != nil {
		return nil, err
	}
	// unwrap the response and return the payload
	fmt.Printf("map response blob %x\n", r)
	resp := &crypto.MapResponse{}
	err = cbor.Unmarshal(r, resp)
	if err != nil {
		return nil, err
	}
	if resp.Status == crypto.StatusNotFound {
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

// rwMap implements ReadWriteTranport using a ReadWriteCap and reference to map client
// The idea is that several streams can share map/client and client/session but
// have different capabilities for the underlying Streams transported by map/client
type rwMap struct {
	c     *Client
	rwCap crypto.ReadWriteCapability
}

// Get implements ReadWriteClient.Get
func (r *rwMap) Get(addr []byte) ([]byte, error) {
	readCap := r.rwCap.ReadCapForAddr(addr)
	return r.c.Get(readCap)
}

// Put implements ReadWriteClient.Put
func (r *rwMap) Put(addr []byte, payload []byte) error {
	writeCap := r.rwCap.WriteCapForAddr(addr, payload)
	return r.c.Put(writeCap)
}

// PayloadSize implements ReadWriteClient.PayloadSize
func (r *rwMap) PayloadSize() int {
	return r.c.PayloadSize()
}

// roMap implements ReadOnlyTranport using a ReadOnlyCap and reference to map client
type roMap struct {
	c     *Client
	roCap *crypto.ReadOnlyCapability
}

// Get implements ReadOnlyClient.Get
func (r *roMap) Get(addr []byte) ([]byte, error) {
	readCap := r.roCap.ReadCapForAddr(addr)
	return r.c.Get(readCap)
}

// PayloadSize implements ReadOnlyClient.PayloadSize
func (r *roMap) PayloadSize() int {
	return r.c.PayloadSize()
}

// woMap implements WriteOnlyClient
type woMap struct {
	c     *Client
	woCap *crypto.WriteOnlyCapability
}

// Put implements WriteOnlyClient.Put
func (w *woMap) Put(addr []byte, payload []byte) error {
	writeCap := w.woCap.WriteCapForAddr(addr, payload)
	return w.c.Put(writeCap)
}

// PayloadSize implements WriteOnlyClient.PayloadSize
func (r *woMap) PayloadSize() int {
	return r.c.PayloadSize()
}

// ReadWrite returns a Transport using map that can read or write with Get() and Put()
func ReadWrite(c *Client, rwCap crypto.ReadWriteCapability) ReadWriteClient {
	m := new(rwMap)
	m.c = c
	m.rwCap = rwCap
	return m
}

// ReadOnly returns a Transport using map that can read with Get() only
func ReadOnly(c *Client, roCap *crypto.ReadOnlyCapability) ReadOnlyClient {
	m := new(roMap)
	m.c = c
	m.roCap = roCap
	return m
}

// WriteOnly returns a Transport using map that can write with Put() only
func WriteOnly(c *Client, woCap *crypto.WriteOnlyCapability) WriteOnlyClient {
	m := new(woMap)
	m.c = c
	m.woCap = woCap
	return m
}

// create a duplex using a shared secret
func DuplexFromSeed(c *Client, initiator bool, seed []byte) ReadWriteClient {
	duplexCap := crypto.DuplexFromSeed(initiator, seed)
	return Duplex(c, duplexCap.ReadOnlyCap, duplexCap.WriteOnlyCap)
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
func Duplex(c *Client, r *crypto.ReadOnlyCapability, w *crypto.WriteOnlyCapability) ReadWriteClient {
	s := new(duplex)
	s.wo = WriteOnly(c, w)
	s.ro = ReadOnly(c, r)
	return s
}

func init() {
	b, _ := cbor.Marshal(crypto.MapRequest{})
	cborFrameOverhead = len(b)
}

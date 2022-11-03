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
	"github.com/katzenpost/katzenpost/core/crypto/rand"
	"github.com/katzenpost/katzenpost/map/common"
	"sort"
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
	temporalStorageId.Write(ID[:])
	temporalStorageId.Write(doc.PriorSharedRandom[0])
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

	r, err := c.Session.BlockingSendReliableMessage(loc.Name(), loc.Provider(), serialized)
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
		return nil, errors.New("StatusNoFound")
	}
	return resp.Payload, nil
}

func NewClient(session *client.Session) (*Client, error) {
	return &Client{Session: session}, nil
}

type Stream interface {
	Read([]byte) (int, error)
	Write([]byte) (int, error)
	Close() error
}

type Block interface {
	ID() (common.MessageID, error)
	Payload() []byte
	Size() int // XXX: necessary?
}

type block struct {
	id      common.MessageID
	payload []byte
}

func (b *block) ID() (common.MessageID, error) {
	return b.id, nil
}
func (b *block) Payload() []byte {
	return b.payload
}
func (b *block) Size() int {
	return len(b.payload)
}

// Encryptor is the interface used by Stream to encrypt each block and determine its storage location
// Next() must return a valid ID before Encrypt will be called, ie Next() must be callable before Encrypt() or Decrypt() are called for the first time, but it is valid for a call to Next() to return error e.g. if the Encryptor is waiting for state derived from Decrypt.
type Encryptor interface {
	Encrypt([]byte) ([]byte, error)
	Decrypt([]byte) ([]byte, error)
	Next() (common.MessageID, error)
}

// SimpleStream implements a forward stream with no acknowledgements or reliability
type SimpleStream struct {
	rand   rand.DeterministicRandReader
	head   *block   // read pointer to the current block
	seek   int      // pointer inside current block payload
	blocks []*block // blocks contain chunked streamed data
}

// Read implements Stream.Read
func (s *SimpleStream) Read(buf []byte) (int, error) {
	switch len(s.blocks) {
	case 0:
		return 0, errors.New("ReadOnEmpty")
	}

	var n int
	for {
		b := buf[n:] // b is pointer to position in output
		l := len(s.head.Payload()[s.seek:])
		if l > len(b) {
			nn := copy(b, s.head.Payload()[s.seek:])
			n += nn
			s.seek += nn
			return n, nil
		} else if l < len(b) {
			n += copy(b, s.head.Payload()[s.seek:])
			s.seek = 0
			if len(s.blocks) > 1 {
				s.blocks = s.blocks[1:]
				s.head = s.blocks[0]
				mm := copy(b[l:], s.head.Payload()[s.seek:])
				s.seek += mm
				n += mm
				continue
			} else {
				// XXX no more blocks...
				return n, errors.New("ReadShort")
			}
		} else if l == len(b) {
			n += copy(b, s.head.Payload()[s.seek:])
			return n, nil
		}
	}
	copy(buf, s.head.Payload()[s.seek:])

	// fill buf with the contents of s.blocks
	for n := 0; n < len(buf); n++ {
		// read bytes from the current block until end is reached
		// XXX: aren't there ioutils methods we can use here...????
		if s.seek < len(s.head.Payload()) {
			buf[n] = s.head.Payload()[s.seek]
			copy(buf, s.head.Payload()[s.seek:])
			s.seek++
			continue
		} else {
			// read from next block, and drop the consumed block
			if len(s.blocks) > 1 {
				s.blocks = s.blocks[1:]
				s.head = s.blocks[0]
				s.seek = 1 // buf[s.seek]; s.seek++
				buf[n] = s.head.Payload()[0]
				continue
			}
			return n, errors.New("ReadShort")
		}
	}
	return n, nil
}

// Write implements Stream.Write
func (s *SimpleStream) Write(buf []byte) (int, error) {
	// XXX: wtf
	//tail := 0
	//blocks := [][]byte
	//for ;len(buf[tail:]) > block_size {
	//	b := block{}
	//	b.payload = buf[tail:block_size]
	//	chunk := buf[tail:block_size]
	//	tail += block_size
	//	blocks = append(blocks, chunk)
	//}
	//// pad trailing bytes
	//if buf[tail:]>0 {
	//	// last
	//	chunk := buf[tail:]
	//	b := block{}
	//	b.payload = make([]byte, block_size)
	//	copy(b.payload, buf[tail:])
	//	blocks = append(blocks, b)
	//}

	return 0, errors.New("NotImplemented")
}

// Close implements Stream.Close
func (s *SimpleStream) Close() error {
	return errors.New("NotImplemented")
}

// NewSimpleStream returns a unidirectional stream initialized with Encryptor
func NewSimpleStream(enc Encryptor) *SimpleStream {
	s := &SimpleStream{}
	return s
}

// ReliableStream implements a reliable stream using acknowledgements and retransmissions
type ReliableStream struct {
}

// Read implements Stream.Read
func (s *ReliableStream) Read(buf []byte) (int, error) {
	return 0, errors.New("NotImplemented")
}

// Write implements Stream.Write
func (s *ReliableStream) Write(buf []byte) (int, error) {
	return 0, errors.New("NotImplemented")
}

// Close implements Stream.Close
func (s *ReliableStream) Close() error {
	return errors.New("NotImplemented")
}

// NewReliableStream returns a unidirectional stream initialized with Encryptor
func NewReliableStream(enc Encryptor) *ReliableStream {
	s := &ReliableStream{}
	return s
}

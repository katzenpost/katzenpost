// spool.go - memspool
// Copyright (C) 2019  David Stainton.
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

package main

import (
	"encoding/binary"
	"errors"
	"sync"
	"sync/atomic"

	"github.com/katzenpost/core/crypto/eddsa"
	"github.com/katzenpost/core/crypto/rand"
)

const (
	CreateSpoolCommand     = 0
	PurgeSpoolCommand      = 1
	AppendMessageCommand   = 2
	RetrieveMessageCommand = 3

	SpoolIDSize   = 12
	MessageIDSize = 4
)

type SpoolRequest struct {
	Command   byte
	SpoolID   []byte
	Signature []byte
	PublicKey []byte
	MessageID []byte
	Message   []byte
}

type SpoolResponse struct {
	SpoolID []byte
	Message []byte
	Status  string
}

func handleSpoolRequest(spoolMap *MemSpoolMap, request *SpoolRequest) *SpoolResponse {
	spoolResponse := SpoolResponse{}
	switch request.Command {
	case CreateSpoolCommand:
		publicKey := new(eddsa.PublicKey)
		err := publicKey.FromBytes(request.PublicKey)
		if err != nil {
			spoolResponse.Status = err.Error()
		}
		spoolResponse.Status = "OK"
		spoolID, err := spoolMap.CreateSpool(publicKey, request.Signature)
		spoolResponse.SpoolID = spoolID[:]
	case PurgeSpoolCommand:
		err := spoolMap.PurgeSpool(request.SpoolID, request.Signature)
		if err != nil {
			spoolResponse.Status = err.Error()
		}
		spoolResponse.Status = "OK"
	case AppendMessageCommand:
		err := spoolMap.AppendToSpool(request.SpoolID, request.Message)
		if err != nil {
			spoolResponse.Status = err.Error()
		}
		spoolResponse.Status = "OK"
	case RetrieveMessageCommand:
		messageID := binary.BigEndian.Uint32(request.MessageID)
		message, err := spoolMap.ReadFromSpool(request.SpoolID, request.Signature, messageID)
		if err != nil {
			spoolResponse.Status = err.Error()
		}
		spoolResponse.Status = "OK"
		spoolResponse.Message = message
	}
	return &spoolResponse
}

type MemSpoolMap struct {
	spools *sync.Map
}

func NewMemSpoolMap() *MemSpoolMap {
	return &MemSpoolMap{
		spools: new(sync.Map),
	}
}

// CreateSpool creates a new spool and returns a spool ID or an error.
func (m *MemSpoolMap) CreateSpool(publicKey *eddsa.PublicKey, signature []byte) (*[SpoolIDSize]byte, error) {
	if !publicKey.Verify(signature, publicKey.Bytes()) {
		return nil, errors.New("Spool creation failed, invalid signature")
	}
	spoolID := [SpoolIDSize]byte{}
	_, err := rand.Reader.Read(spoolID[:])
	if err != nil {
		return nil, err
	}
	spool := NewMemSpool(publicKey)
	_, loaded := m.spools.LoadOrStore(spoolID, spool)
	if loaded {
		return nil, errors.New("Spool creation failed, spool ID collision, this should never happen")
	}
	return &spoolID, nil
}

// PurgeSpool delete the spool associated with the given spool ID.
// Returns nil on success or an error.
func (m *MemSpoolMap) PurgeSpool(spoolID []byte, signature []byte) error {
	raw_spool, ok := m.spools.Load(spoolID)
	if !ok {
		return errors.New("spool ID not found in spools map")
	}
	spool, ok := raw_spool.(MemSpool)
	if !ok {
		return errors.New("invalid spool found")
	}
	if !spool.PublicKey().Verify(signature, spool.PublicKey().Bytes()) {
		return errors.New("invalid signature")
	}
	m.spools.Delete(spoolID)
	return nil
}

func (m *MemSpoolMap) AppendToSpool(spoolID []byte, message []byte) error {
	raw_spool, ok := m.spools.Load(spoolID)
	if !ok {
		return errors.New("spool not found")
	}
	spool, ok := raw_spool.(MemSpool)
	if !ok {
		return errors.New("invalid spool found")
	}
	return spool.Append(message)
}

func (m *MemSpoolMap) ReadFromSpool(spoolID []byte, signature []byte, messageID uint32) ([]byte, error) {
	raw_spool, ok := m.spools.Load(spoolID)
	if !ok {
		return nil, errors.New("spool not found")
	}
	spool, ok := raw_spool.(MemSpool)
	if !ok {
		return nil, errors.New("invalid spool found")
	}
	if !spool.PublicKey().Verify(signature, spool.PublicKey().Bytes()) {
		return nil, errors.New("invalid signature")
	}
	return spool.Read(messageID)
}

type MemSpool struct {
	publicKey *eddsa.PublicKey
	items     *sync.Map
	current   uint32
}

func NewMemSpool(publicKey *eddsa.PublicKey) *MemSpool {
	return &MemSpool{
		publicKey: publicKey,
		items:     new(sync.Map),
		current:   0,
	}
}

func (s *MemSpool) PublicKey() *eddsa.PublicKey {
	return s.publicKey
}

func (s *MemSpool) Append(message []byte) error {
	current := atomic.AddUint32(&s.current, 1)
	_, loaded := s.items.LoadOrStore(current, message)
	if loaded {
		return errors.New("append failure, key already in use. wtf.")
	}
	return nil
}

func (s *MemSpool) Read(messageID uint32) ([]byte, error) {
	raw_message, ok := s.items.Load(messageID)
	if !ok {
		return nil, errors.New("message ID not found")
	}
	message, ok := raw_message.([]byte)
	if !ok {
		return nil, errors.New("invalid message found")
	}
	return message, nil
}

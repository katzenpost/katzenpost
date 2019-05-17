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
	"errors"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/katzenpost/core/crypto/eddsa"
	"github.com/katzenpost/core/crypto/rand"
	"github.com/katzenpost/memspool/common"
)

const (
	CreateSpoolCommand     = 0
	PurgeSpoolCommand      = 1
	AppendMessageCommand   = 2
	RetrieveMessageCommand = 3
)

func handleSpoolRequest(spoolMap *MemSpoolMap, request *common.SpoolRequest) *common.SpoolResponse {
	log.Debug("start of handle spool request")
	spoolResponse := common.SpoolResponse{}
	spoolID := [common.SpoolIDSize]byte{}
	copy(spoolID[:], request.SpoolID)
	switch request.Command {
	case CreateSpoolCommand:
		log.Debug("create spool")
		publicKey := new(eddsa.PublicKey)
		err := publicKey.FromBytes(request.PublicKey)
		if err != nil {
			spoolResponse.Status = err.Error()
			log.Error(spoolResponse.Status)
			return &spoolResponse
		}
		spoolResponse.Status = "OK"
		spoolID, err := spoolMap.CreateSpool(publicKey, request.Signature)
		if err != nil {
			spoolResponse.Status = err.Error()
			log.Error(spoolResponse.Status)
			return &spoolResponse
		}
		spoolResponse.SpoolID = spoolID[:]
	case PurgeSpoolCommand:
		log.Debug("purge spool")
		err := spoolMap.PurgeSpool(spoolID, request.Signature)
		if err != nil {
			spoolResponse.Status = err.Error()
			log.Error(spoolResponse.Status)
			return &spoolResponse
		}
		spoolResponse.Status = "OK"
	case AppendMessageCommand:
		log.Debugf("append to spool, with spool ID: %d", request.SpoolID)
		err := spoolMap.AppendToSpool(spoolID, request.Message)
		log.Debug("after call to AppendToSpool")
		if err != nil {
			spoolResponse.Status = err.Error()
			log.Error(spoolResponse.Status)
			return &spoolResponse
		}
		spoolResponse.Status = "OK"
	case RetrieveMessageCommand:
		log.Debug("read from spool")
		log.Debugf("before ReadFromSpool with message ID %d", request.MessageID)
		message, err := spoolMap.ReadFromSpool(spoolID, request.Signature, request.MessageID)
		log.Debug("after ReadFromSpool")
		if err != nil {
			spoolResponse.Status = err.Error()
			log.Error(spoolResponse.Status)
			return &spoolResponse
		}
		spoolResponse.Status = "OK"
		spoolResponse.Message = message
	}
	log.Debug("end of handle spool request")
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
func (m *MemSpoolMap) CreateSpool(publicKey *eddsa.PublicKey, signature []byte) (*[common.SpoolIDSize]byte, error) {
	if !publicKey.Verify(signature, publicKey.Bytes()) {
		return nil, errors.New("Spool creation failed, invalid signature")
	}
	spoolID := [common.SpoolIDSize]byte{}
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
func (m *MemSpoolMap) PurgeSpool(spoolID [common.SpoolIDSize]byte, signature []byte) error {
	raw_spool, ok := m.spools.Load(spoolID)
	if !ok {
		return errors.New("spool ID not found in spools map")
	}
	spool, ok := raw_spool.(*MemSpool)
	if !ok {
		return errors.New("invalid spool found")
	}
	if !spool.PublicKey().Verify(signature, spool.PublicKey().Bytes()) {
		return errors.New("invalid signature")
	}
	m.spools.Delete(spoolID)
	return nil
}

func (m *MemSpoolMap) AppendToSpool(spoolID [common.SpoolIDSize]byte, message []byte) error {
	log.Debug("start of AppendToSpool")
	raw_spool, ok := m.spools.Load(spoolID)
	if !ok {
		log.Debug("spool not found")
		return errors.New("spool not found")
	}
	log.Debug("after Load spool")
	spool, ok := raw_spool.(*MemSpool)
	log.Debug("after type assertion")
	if !ok {
		log.Debug("invalid spool found")
		return errors.New("invalid spool found")
	}
	log.Debug("end of AppendToSpool")
	return spool.Append(message)
}

func (m *MemSpoolMap) ReadFromSpool(spoolID [common.SpoolIDSize]byte, signature []byte, messageID uint32) ([]byte, error) {
	raw_spool, ok := m.spools.Load(spoolID)
	if !ok {
		return nil, errors.New("spool not found")
	}
	spool, ok := raw_spool.(*MemSpool)
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
		return nil, fmt.Errorf("message ID %d not found", messageID)
	}
	message, ok := raw_message.([]byte)
	if !ok {
		return nil, errors.New("invalid message found")
	}
	return message, nil
}

// client.go - Reunion client.
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

// Package client provides the Reunion protocol client.
package client

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/katzenpost/reunion/commands"
	"github.com/katzenpost/reunion/crypto"
	"github.com/katzenpost/reunion/server"
	"github.com/ugorji/go/codec"
	"gopkg.in/op/go-logging.v1"
)

var cborHandle = new(codec.CborHandle)

// ShutdownErrMessage is an error invoked during shutdown.
var ShutdownErrMessage = "reunion: shutdown requested"

// InvalidResponseErrMessage is an error used to indicate
// that an invalid response from the Reunion server was received.
var InvalidResponseErrMessage = "invalid response received from Reunion DB"

const (
	initialState       = 0
	t1MessageSentState = 1
	t2MessageSentState = 2
	t3MessageSentState = 3
)

// ReunionUpdate represents an update to the reunion client state or
// to report a failure.
type ReunionUpdate struct {
	// ContactID is the unique contact identity.
	ContactID uint64
	// Error contains an error or nil if no error.
	Error error
	// Serialized is the serialized Exchange state.
	Serialized []byte
	// Result is the received decrypted T1 message payload.
	Result []byte
}

type exchangeCbor struct {
	Status      int
	ContactID   uint64
	Epoch       uint64
	Client      *crypto.Client
	SentT1      []byte
	SentT2Map   map[[32]byte][]byte
	SentT3Map   map[[32]byte][]byte
	ReceivedT2s map[[32]byte][]byte
}

// Exchange encapsulates all the client key material and
// protocol state transitions.
//
// The Reunion paper states:
//
// For the linked protocol variant:
// For every other t1 message, they construct and
// transmit a respective t2 message.
// For every t2 message sent in reply to their own t1,
// they construct and transmit a t3 message.
type Exchange struct {
	log          *logging.Logger
	updateChan   chan ReunionUpdate
	db           commands.ReunionDatabase
	shutdownChan chan interface{}

	status            int
	contactID         uint64
	epoch             uint64
	sharedRandomValue []byte

	client *crypto.Client

	payload          []byte
	sentT1           []byte
	sentT2Map        map[[32]byte][]byte
	sentT3Map        map[[32]byte][]byte
	receivedT1s      map[[32]byte][]byte
	receivedT2s      map[[32]byte][]byte
	receivedT3s      map[[32]byte][]byte
	receivedT1Alphas []*crypto.PublicKey
	remoteSequence   uint64
}

// NewExchange creates a new Exchange struct type.
func NewExchange(
	payload []byte,
	log *logging.Logger,
	db commands.ReunionDatabase,
	contactID uint64,
	passphrase []byte,
	sharedRandomValue []byte,
	epoch uint64,
	updateChan chan ReunionUpdate) (*Exchange, error) {

	client, err := crypto.NewClient(passphrase, sharedRandomValue, epoch)
	if err != nil {
		return nil, err
	}
	return &Exchange{
		log:               log,
		updateChan:        updateChan,
		db:                db,
		shutdownChan:      make(chan interface{}),
		status:            initialState,
		contactID:         contactID,
		epoch:             epoch,
		sharedRandomValue: sharedRandomValue,
		client:            client,
		payload:           payload,
		sentT1:            nil,
		sentT2Map:         make(map[[32]byte][]byte),
		sentT3Map:         make(map[[32]byte][]byte),
		receivedT1s:       make(map[[32]byte][]byte),
		receivedT2s:       make(map[[32]byte][]byte),
		receivedT3s:       make(map[[32]byte][]byte),
	}, nil
}

// Marshal returns a serialization of the Exchange or an error.
func (e *Exchange) Marshal() ([]byte, error) {
	ex := exchangeCbor{
		ContactID:   e.contactID,
		Status:      e.status,
		Epoch:       e.epoch,
		Client:      e.client,
		SentT1:      e.sentT1,
		SentT2Map:   e.sentT2Map,
		SentT3Map:   e.sentT3Map,
		ReceivedT2s: e.receivedT2s,
	}
	var serialized []byte
	err := codec.NewEncoderBytes(&serialized, cborHandle).Encode(&ex)
	if err != nil {
		return nil, err
	}
	return serialized, nil
}

func (e *Exchange) shouldStop() bool {
	select {
	case <-e.shutdownChan:
		return true
	default:
		return false
	}

	// unreachable
}

func (e *Exchange) sentUpdateOK() bool {
	serialized, err := e.Marshal()
	e.updateChan <- ReunionUpdate{
		ContactID:  e.contactID,
		Error:      err,
		Serialized: serialized,
	}
	if err != nil {
		return false
	}
	return true

}

func (e *Exchange) fetchState() (bool, error) {
	fetchStateCmd := new(commands.FetchState)
	fetchStateCmd.Epoch = e.epoch
	rawResponse, err := e.db.Query(fetchStateCmd, e.shutdownChan)
	if err != nil {
		return false, err
	}
	response, ok := rawResponse.(*commands.StateResponse)
	if !ok {
		return false, errors.New("fetch state: wrong response command received")
	}
	if response.ErrorCode != commands.ResponseStatusOK {
		return false, fmt.Errorf("fetch state: received an error status code from the reunion db: %d", response.ErrorCode)
	}
	chunk := new(server.ReunionStateChunk)
	err = codec.NewDecoderBytes(response.Payload, cborHandle).Decode(chunk)
	if err != nil {
		return false, err
	}
	if response.Truncated {
		return false, errors.New("truncated Reunion DB state not yet supported")
	}
	if chunk.Sequence > e.remoteSequence {
		e.processState(chunk)
		return true, nil
	}
	return false, nil
}

func (e *Exchange) processState(chunk *server.ReunionStateChunk) bool {
	hasNew := false
	for _, t1 := range chunk.T1s {
		h := sha256.New()
		h.Write([]byte(t1.Payload))
		t1Hash := h.Sum(nil)
		t1HashAr := [sha256.Size]byte{}
		copy(t1HashAr[:], t1Hash)
		_, ok := e.receivedT1s[t1HashAr]
		if !ok {
			e.receivedT1s[t1HashAr] = t1.Payload
			hasNew = true
		}
	}
	h := sha256.New()
	h.Write([]byte(e.sentT1))
	myT1Hash := h.Sum(nil)
	for _, sendT2 := range chunk.T2s {
		if !bytes.Equal(sendT2.T1Hash[:], myT1Hash) {
			continue
		}
		h := sha256.New()
		h.Write(sendT2.Payload)
		t2Hash := h.Sum(nil)
		t2HashAr := [sha256.Size]byte{}
		copy(t2HashAr[:], t2Hash)
		if _, ok := e.receivedT2s[t2HashAr]; !ok {
			e.receivedT2s[t2HashAr] = sendT2.Payload
			hasNew = true
		}
	}
	for _, sendT3 := range chunk.T3s {
		if _, ok := e.sentT2Map[sendT3.T2Hash]; !ok {
			continue
		}
		h := sha256.New()
		h.Write(sendT3.Payload)
		t3Hash := h.Sum(nil)
		t3HashAr := [sha256.Size]byte{}
		copy(t3HashAr[:], t3Hash)
		if _, ok := e.receivedT3s[t3HashAr]; !ok {
			e.receivedT3s[sendT3.T2Hash] = sendT3.Payload
			hasNew = true
		}
	}
	return hasNew
}

func (e *Exchange) sendT1() bool {
	var err error
	e.sentT1, err = e.client.GenerateType1Message(e.epoch, e.sharedRandomValue, e.payload)
	if err != nil {
		e.log.Error(err.Error())
		return false
	}
	t1Cmd := commands.SendT1{
		Epoch:   e.epoch,
		Payload: e.sentT1,
	}
	rawResponse, err := e.db.Query(&t1Cmd, e.shutdownChan)
	if err != nil {
		e.log.Error(err.Error())
		return false
	}
	response, ok := rawResponse.(*commands.MessageResponse)
	if !ok {
		e.log.Error(InvalidResponseErrMessage)
		return false
	}
	if response.ErrorCode != commands.ResponseStatusOK {
		e.log.Errorf("received an error status code from the reunion db: %d", response.ErrorCode)
		return false
	}
	return true
}

func (e *Exchange) sendT2Messages() bool {
	for _, t1 := range e.receivedT1s {
		// decrypt alpha pub key and store it in our state
		alpha, _, _, err := crypto.DecodeT1Message(t1)
		if err != nil {
			e.log.Error(err.Error())
			return false
		}
		t2, alphaPubKey, err := e.client.ProcessType1MessageAlpha(alpha, e.sharedRandomValue, e.epoch)
		if err != nil {
			e.log.Error(err.Error())
			return false
		}
		e.receivedT1Alphas = append(e.receivedT1Alphas, alphaPubKey)

		h := sha256.New()
		h.Write(t2)
		t2Hash := h.Sum(nil)
		t2HashAr := [sha256.Size]byte{}
		copy(t2HashAr[:], t2Hash)

		e.sentT2Map[t2HashAr] = t2

		// reply with t2 and t1 hash
		h = sha256.New()
		h.Write([]byte(t1))
		t1Hash := h.Sum(nil)
		t1HashAr := [sha256.Size]byte{}
		copy(t1HashAr[:], t1Hash)
		t2Cmd := commands.SendT2{
			Epoch:   e.epoch,
			T1Hash:  t1HashAr,
			Payload: t2,
		}
		rawResponse, err := e.db.Query(&t2Cmd, e.shutdownChan)
		if err != nil {
			e.log.Error(err.Error())
			return false
		}
		response, ok := rawResponse.(*commands.MessageResponse)
		if !ok {
			e.log.Error(InvalidResponseErrMessage)
			return false
		}
		if response.ErrorCode != commands.ResponseStatusOK {
			e.log.Errorf("received an error status code from the reunion db: %d", response.ErrorCode)
			return false
		}
	}
	return true
}

func (e *Exchange) sendT3Messages() bool {
	/*

	    for t2Hash, t2 := range e.receivedT2s {

			candidateKey, err := client1.GetCandidateKey(t2, alphaPubKey, e.epoch, sharedRandomValue)
			if err != nil {
				e.log.Error(err.Error())
				return false
			}

		}


			h := sha256.New()
			h.Write([]byte(t1.Payload))
			t1Hash := h.Sum(nil)
			_, ok := e.receivedT2s[t1Hash]
			if ok {
				e.log.Error("weird error, duplicate t1 hash found for received t2")
				return false
			}
			e.receivedT2s[t1Hash] = t2
	*/
	return false
}

// Run performs the Reunion exchange and expresses a simple
// FSM which uses the updateChan to save it's state after each
// state transition. This method is meant to run in it's own
// goroutine.
func (e *Exchange) Run() {
	switch e.status {
	case initialState:
		// XXX not required -> 1:A <- DB: fetch current epoch and current set of data for epoch state
		// 2:A -> DB: transmit א message
		if !e.sendT1() {
			return
		}
		e.status = t1MessageSentState
		if !e.sentUpdateOK() {
			return
		}
		if e.shouldStop() {
			e.log.Error(ShutdownErrMessage)
			return
		}
		fallthrough
	case t1MessageSentState:
		// 3:A <- DB: fetch epoch state
		// 4:A -> DB: transmit one ב message for each א
		if !e.sendT2Messages() {
			return
		}
		e.status = t2MessageSentState
		if !e.sentUpdateOK() {
			return
		}
		if e.shouldStop() {
			e.log.Error(ShutdownErrMessage)
			return
		}
		// 5:A <- DB: fetch epoch state for replies to A’s א
		// 6:A -> DB: transmit one ג message for each new ב
		if !e.sendT3Messages() {
			return
		}
		e.status = t3MessageSentState
		if !e.sentUpdateOK() {
			return
		}
		if e.shouldStop() {
			e.log.Error(ShutdownErrMessage)
			return
		}
		fallthrough
	case t3MessageSentState:
		// 7:A <- DB: fetch epoch state for replies to A’s
		// 8:A -> DB: continue sending ב and ג messages until epoch ends
		// 9:A <- DB: fetch state and confirm epoch end by retrieving new epoch
		// XXX
	default:
		e.updateChan <- ReunionUpdate{
			ContactID: e.contactID,
			Error:     errors.New("unknown state"),
		}
		return
	}

	// unreachable

}

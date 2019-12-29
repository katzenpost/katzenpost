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
	"errors"

	"github.com/katzenpost/reunion/commands"
	"github.com/katzenpost/reunion/crypto"
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
	ContactID  uint64
	Error      error
	Serialized []byte
	Result     []byte
}

type exchangeCbor struct {
	Status      int
	ContactID   uint64
	Epoch       uint64
	Client      *crypto.Client
	T1          []byte
	SentT2Map   map[[32]byte][]byte
	SentT3Map   map[[32]byte][]byte
	ReceivedT2s map[[32]byte]bool
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

	payload     []byte
	t1          []byte
	sentT2Map   map[[32]byte][]byte
	sentT3Map   map[[32]byte][]byte
	receivedT2s map[[32]byte]bool
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
		t1:                nil,
		sentT2Map:         make(map[[32]byte][]byte),
		sentT3Map:         make(map[[32]byte][]byte),
		receivedT2s:       make(map[[32]byte]bool),
	}, nil
}

// Marshal returns a serialization of the Exchange or an error.
func (e *Exchange) Marshal() ([]byte, error) {
	ex := exchangeCbor{
		ContactID:   e.contactID,
		Status:      e.status,
		Epoch:       e.epoch,
		Client:      e.client,
		T1:          e.t1,
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

func (e *Exchange) sendT1() bool {
	t1, err := e.client.GenerateType1Message(e.epoch, e.sharedRandomValue, e.payload)
	if err != nil {
		e.log.Error(err.Error())
		return false
	}
	sendT1Cmd := commands.SendT1{
		Epoch:   e.epoch,
		Payload: t1,
	}
	rawResponse, err := e.db.Query(&sendT1Cmd, e.shutdownChan)
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

func (e *Exchange) fetchState() bool {
	return false // XXX
}

// Run performs the Reunion exchange and expresses a simple
// FSM which uses the updateChan to save it's state after each
// state transition. This method is meant to run in it's own
// goroutine.
func (e *Exchange) Run() {
	switch e.status {
	case initialState:
		// XXX 1:A <- DB: fetch current epoch and current set of data for epoch state
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
		// XXX
		e.status = t2MessageSentState
		if !e.sentUpdateOK() {
			return
		}
		if e.shouldStop() {
			e.log.Error(ShutdownErrMessage)
			return
		}
		fallthrough
	case t2MessageSentState:
		// 5:A <- DB: fetch epoch state for replies to A’s א
		// 6:A -> DB: transmit one ג message for each new ב
		// XXX
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

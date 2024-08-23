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
	"math/rand"

	"github.com/katzenpost/katzenpost/reunion/commands"
	"github.com/katzenpost/katzenpost/reunion/crypto"
	"github.com/katzenpost/katzenpost/reunion/server"
	"gopkg.in/op/go-logging.v1"
)

var (
	// InvalidResponseErr is an error used to indicate
	// that an invalid response from the Reunion server was received.
	InvalidResponseErr = errors.New("invalid response received from Reunion DB")

	// ErrShutdown is an error invoked during shutdown.
	ErrShutdown = errors.New("reunion: shutdown requested")
)

const (
	initialState       = 0
	t1MessageSentState = 1
)

// ExchangeHash is a 32 byte array which represents a hash of
// one of our cryptographic messages, t1 hash, t2 hash etc.
type ExchangeHash [32]byte

// ReunionUpdate represents an update to the reunion client state or
// to report a failure.
type ReunionUpdate struct {
	// ContactID is the unique contact identity.
	ContactID uint64
	// ExchangeID is the unique reunion exchange identity.
	ExchangeID uint64
	// Error contains an error or nil if no error.
	Error error
	// Serialized is the serialized Exchange state.
	Serialized []byte
	// Result is the received decrypted T1 message payload.
	Result []byte
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
	db           server.ReunionDatabase
	shutdownChan chan struct{}

	status     int
	contactID  uint64
	ExchangeID uint64
	session    *crypto.Session

	payload []byte

	sentT1 []byte

	// t2 hash -> t2
	sentT2Map map[ExchangeHash][]byte

	// t1 hash -> t1
	repliedT1s map[ExchangeHash][]byte
	// t2 hash -> t2
	repliedT2s map[ExchangeHash][]byte

	// t1 hash -> t1
	receivedT1s map[ExchangeHash][]byte

	// src t1 hash -> t2
	receivedT2s map[ExchangeHash][]byte

	// src t1 hash -> t3
	receivedT3s map[ExchangeHash][]byte

	// t1 hash -> unelligator'ed t1 alpha pub key
	receivedT1Alphas map[ExchangeHash]*crypto.PublicKey

	// t1 hash -> beta
	decryptedT1Betas map[ExchangeHash]*crypto.PublicKey
}

// NewExchangeFromSnapshot creates a new Exchange given a snapshot blob.
func NewExchangeFromSnapshot(
	serialized []byte,
	log *logging.Logger,
	db server.ReunionDatabase,
	updateChan chan ReunionUpdate,
	shutdownChan chan struct{}) (*Exchange, error) {

	ex := &Exchange{
		log:          log,
		updateChan:   updateChan,
		db:           db,
		shutdownChan: shutdownChan,
	}
	err := ex.Unmarshal(serialized)
	if err != nil {
		return ex, err
	}

	// Fetch the current SharedRandoms and Epochs
	srvs, err := db.CurrentSharedRandoms()
	if err != nil {
		return ex, err
	}
	epochs, err := db.CurrentEpochs()
	if err != nil {
		return ex, err
	}

	// Verify that the session epoch is still valid
	current := false
	for _, ep := range epochs {
		if ex.session.Epoch() == ep {
			current = true
		}
	}
	if !current {
		return ex, errors.New("Epoch has expired, cannot resume exchange")
	}
	current = false

	// Verify that the session shared random is still valid
	ssrv := ex.session.SharedRandom()
	for _, srv := range srvs {
		if bytes.Equal(srv, ssrv) {
			current = true
		}
	}
	if !current {
		return ex, errors.New("SharedRandom has expired, cannot resume exchange")
	}
	return ex, nil
}

// NewExchange creates a new Exchange struct type.
func NewExchange(
	payload []byte,
	log *logging.Logger,
	db server.ReunionDatabase,
	contactID uint64,
	passphrase []byte,
	sharedRandomValue []byte,
	epoch uint64,
	updateChan chan ReunionUpdate,
	shutdownChan chan struct{}) (*Exchange, error) {

	session, err := crypto.NewSession(passphrase, sharedRandomValue, epoch)
	if err != nil {
		return nil, err
	}
	return &Exchange{
		log:          log,
		updateChan:   updateChan,
		db:           db,
		shutdownChan: shutdownChan,
		status:       initialState,
		contactID:    contactID,
		ExchangeID:   rand.Uint64(),
		session:      session,
		payload:      payload,

		sentT1:    nil,
		sentT2Map: make(map[ExchangeHash][]byte),

		receivedT1s: make(map[ExchangeHash][]byte),
		receivedT2s: make(map[ExchangeHash][]byte),
		receivedT3s: make(map[ExchangeHash][]byte),

		repliedT1s: make(map[ExchangeHash][]byte),
		repliedT2s: make(map[ExchangeHash][]byte),

		receivedT1Alphas: make(map[ExchangeHash]*crypto.PublicKey),
		decryptedT1Betas: make(map[ExchangeHash]*crypto.PublicKey),
	}, nil
}

// Unmarshal returns an error if the given data fails to be deserialized.
func (e *Exchange) Unmarshal(data []byte) error {
	state := new(serializableExchange)
	err := state.Unmarshal(data)
	if err != nil {
		return fmt.Errorf("wtf unmarshal failure: %s", err.Error())
	}
	e.contactID = state.ContactID
	e.ExchangeID = state.ExchangeID
	e.status = state.Status
	e.session = state.Session
	e.sentT1 = state.SentT1
	e.sentT2Map = state.SentT2Map
	e.receivedT1s = state.ReceivedT1s
	e.receivedT2s = state.ReceivedT2s
	e.receivedT3s = state.ReceivedT3s
	e.repliedT1s = state.RepliedT1s
	e.repliedT2s = state.RepliedT2s
	e.receivedT1Alphas = state.ReceivedT1Alphas
	e.decryptedT1Betas = state.DecryptedT1Betas
	return nil
}

// Marshal returns a serialization of the Exchange or an error.
// XXX fix me; added many more fields since this was written...
func (e *Exchange) Marshal() ([]byte, error) {
	ex := serializableExchange{
		ContactID:        e.contactID,
		Status:           e.status,
		Session:          e.session,
		SentT1:           e.sentT1,
		SentT2Map:        e.sentT2Map,
		ReceivedT1s:      e.receivedT1s,
		ReceivedT2s:      e.receivedT2s,
		ReceivedT3s:      e.receivedT3s,
		RepliedT1s:       e.repliedT1s,
		RepliedT2s:       e.repliedT2s,
		ReceivedT1Alphas: e.receivedT1Alphas,
		DecryptedT1Betas: e.decryptedT1Betas,
	}
	return ex.Marshal()
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
		ExchangeID: e.ExchangeID,
		Error:      err,
		Serialized: serialized,
		Result:     nil,
	}
	if err != nil {
		return false
	}
	return true

}

func (e *Exchange) processState(state *server.RequestedReunionState) (bool, error) {
	hasNew := false
	for t1hash, t1 := range state.T1Map {
		if _, ok := e.receivedT1s[t1hash]; !ok {
			e.receivedT1s[t1hash] = t1
			hasNew = true
		}
	}
	for _, message := range state.Messages {
		if len(message.T2Payload) > 0 {
			if _, ok := e.receivedT2s[message.SrcT1Hash]; !ok {
				e.receivedT2s[message.SrcT1Hash] = message.T2Payload
				hasNew = true
			}
		} else if len(message.T3Payload) > 0 {
			if _, ok := e.receivedT3s[message.SrcT1Hash]; !ok {
				e.receivedT3s[message.SrcT1Hash] = message.T3Payload
				hasNew = true
			}
		} else {
			return false, errors.New("wtf, invalid message found")
		}
	}
	return hasNew, nil
}

func (e *Exchange) fetchState() error {
	h := sha256.New()
	h.Write(e.sentT1)
	t1Hash := h.Sum(nil)
	t1HashAr := [sha256.Size]byte{}
	copy(t1HashAr[:], t1Hash)

	fetchStateCmd := new(commands.FetchState)
	fetchStateCmd.Epoch = e.session.Epoch()
	fetchStateCmd.T1Hash = t1HashAr

	rawResponse, err := e.db.Query(fetchStateCmd)
	if err != nil {
		return err
	}
	response, ok := rawResponse.(*commands.StateResponse)
	if !ok {
		return errors.New("fetch state: wrong response command received")
	}
	if response.ErrorCode != commands.ResponseStatusOK {
		return fmt.Errorf("fetch state: received an error status code from the reunion db: %d", response.ErrorCode)
	}
	state := new(server.RequestedReunionState)
	err = state.Unmarshal(response.Payload)
	if err != nil {
		return err
	}
	if response.Truncated {
		return errors.New("truncated Reunion DB state not yet supported")
	}
	_, err = e.processState(state)
	return err
}

func (e *Exchange) sendT1() error {
	var err error
	e.sentT1, err = e.session.GenerateType1Message(e.payload)
	if err != nil {
		return err
	}
	t1Cmd := commands.SendT1{
		Epoch:   e.session.Epoch(),
		Payload: e.sentT1,
	}
	rawResponse, err := e.db.Query(&t1Cmd)
	if err != nil {
		return err
	}
	response, ok := rawResponse.(*commands.MessageResponse)
	if !ok {
		return InvalidResponseErr
	}
	if response.ErrorCode != commands.ResponseStatusOK {
		return fmt.Errorf("received an error status code from the reunion db: %d", response.ErrorCode)
	}
	return nil
}

func (e *Exchange) sendT2Messages() error {
	hasSent := false

	h := sha256.New()
	h.Write([]byte(e.sentT1))
	myT1Hash := h.Sum(nil)
	myT1HashAr := [sha256.Size]byte{}
	copy(myT1HashAr[:], myT1Hash)

	for t1Hash, t1 := range e.receivedT1s {
		if bytes.Equal(t1Hash[:], myT1Hash) {
			continue
		}

		_, ok := e.repliedT1s[t1Hash]
		if ok {
			continue
		}

		// decrypt alpha pub key and store it in our state
		alpha, _, _, err := crypto.DecodeT1Message(t1)
		if err != nil {
			return err
		}
		t2, alphaPubKey, err := e.session.ProcessType1MessageAlpha(alpha)
		if err != nil {
			return err
		}

		e.receivedT1Alphas[t1Hash] = alphaPubKey

		h := sha256.New()
		h.Write(t2)
		t2Hash := h.Sum(nil)
		t2HashAr := [sha256.Size]byte{}
		copy(t2HashAr[:], t2Hash)

		e.sentT2Map[t2HashAr] = t2

		// reply with t2 and t1 hash
		t2Cmd := commands.SendT2{
			Epoch:     e.session.Epoch(),
			SrcT1Hash: myT1HashAr,
			DstT1Hash: t1Hash,
			Payload:   t2,
		}
		rawResponse, err := e.db.Query(&t2Cmd)
		if err != nil {
			return err
		}
		response, ok := rawResponse.(*commands.MessageResponse)
		if !ok {
			return InvalidResponseErr
		}
		if response.ErrorCode != commands.ResponseStatusOK {
			return fmt.Errorf("received an error status code from the reunion db: %d", response.ErrorCode)
		}
		e.repliedT1s[t1Hash] = t1
		hasSent = true
	}
	if hasSent {
		return nil
	}
	return fmt.Errorf("Failed to send T2 Messages!")
}

func (e *Exchange) sendT3Messages() error {
	hasSentT3 := false

	h := sha256.New()
	h.Write([]byte(e.sentT1))
	myT1Hash := h.Sum(nil)
	myT1HashAr := [sha256.Size]byte{}
	copy(myT1HashAr[:], myT1Hash)

	for srcT1Hash, t2 := range e.receivedT2s {
		t1, ok := e.receivedT1s[srcT1Hash]
		if !ok {
			return fmt.Errorf("error, t1 hash %x missing from map", srcT1Hash[:])
		}
		h := sha256.New()
		h.Write(t2)
		t2Hash := h.Sum(nil)
		t2HashAr := [sha256.Size]byte{}
		copy(t2HashAr[:], t2Hash)

		if _, ok := e.repliedT2s[t2HashAr]; ok {
			continue
		}
		alphaKey, ok := e.receivedT1Alphas[srcT1Hash]
		if !ok {
			return fmt.Errorf("Failed to send T3 message because no T1 Alpha was found")
		}
		candidateKey, err := e.session.GetCandidateKey(t2, alphaKey)
		if err != nil {
			return err
		}
		_, t1beta, _, err := crypto.DecodeT1Message(t1)
		if err != nil {
			return err
		}
		beta, err := crypto.DecryptT1Beta(candidateKey, t1beta)
		if err != nil {
			e.log.Error(err.Error())
			continue
		}
		t3, err := e.session.ComposeType3Message(beta)
		if err != nil {
			return err
		}
		sendT3Cmd := commands.SendT3{
			Epoch:     e.session.Epoch(),
			SrcT1Hash: myT1HashAr,
			DstT1Hash: srcT1Hash,
			Payload:   t3,
		}
		rawResponse, err := e.db.Query(&sendT3Cmd)
		if err != nil {
			return err
		}
		response, ok := rawResponse.(*commands.MessageResponse)
		if !ok {
			return InvalidResponseErr
		}
		if response.ErrorCode != commands.ResponseStatusOK {
			return fmt.Errorf("received an error status code from the reunion db: %d", response.ErrorCode)
		}

		e.decryptedT1Betas[srcT1Hash] = beta

		e.repliedT2s[t2HashAr] = t2
		hasSentT3 = true
	}
	if hasSentT3 {
		return nil
	}
	return fmt.Errorf("Failed to send T3 Messages!")
}

func (e *Exchange) processT3Messages() bool {
	processed := false
	for srcT1Hash, t3 := range e.receivedT3s {
		beta, ok := e.decryptedT1Betas[srcT1Hash]
		if !ok {
			continue
		}
		t1, ok := e.receivedT1s[srcT1Hash]
		if !ok {
			e.log.Error("error, t1 missing from map")
			return false
		}
		_, _, gamma, err := crypto.DecodeT1Message(t1)
		if err != nil {
			e.log.Debug("decode t1 message failure")
			e.log.Error(err.Error())
			return false
		}
		plaintext, err := e.session.ProcessType3Message(t3, gamma, beta)
		if err != nil {
			e.log.Errorf("ProcessType3Message failure: %s", err.Error())
			return false
		}
		e.updateChan <- ReunionUpdate{
			ExchangeID: e.ExchangeID,
			ContactID:  e.contactID,
			Error:      nil,
			Serialized: nil,
			Result:     plaintext,
		}
		processed = true
	}
	return processed
}

// Run performs the Reunion exchange and expresses a simple
// FSM which uses the updateChan to save it's state after each
// state transition. This method is meant to run in it's own
// goroutine.
func (e *Exchange) Run() {
	defer e.log.Debug("Run was halted.")
	haltedfn := func() {
		e.updateChan <- ReunionUpdate{
			ExchangeID: e.ExchangeID,
			ContactID:  e.contactID,
			Error:      errors.New("Run was halted."),
		}
	}

	switch e.status {
	case initialState:
		// XXX not required -> 1:A <- DB: fetch current epoch and current set of data for epoch state
		// 2:A -> DB: transmit א message
		for {
			err := e.sendT1()
			if err != nil {
				defer haltedfn()
				return
			}
			break
		}
		e.status = t1MessageSentState
		if !e.sentUpdateOK() {
			defer haltedfn()
			return
		}
		if e.shouldStop() {
			e.log.Error(ErrShutdown.Error())
			defer haltedfn()
			return
		}
		fallthrough
	case t1MessageSentState:
		for {
			// 3:A <- DB: fetch epoch state
			err := e.fetchState()
			// if failure due to timeout, retransmit
			if err != nil {
				e.log.Error(err.Error())
				defer haltedfn()
				return
			}
			// 4:A -> DB: transmit one ב message for each א
			if err := e.sendT2Messages(); err != nil {
				e.log.Error(err.Error())
			} else {
				e.log.Debug("Sent T2 Messages successfully")
			}

			if !e.sentUpdateOK() {
				defer haltedfn()
				return
			}
			if e.shouldStop() {
				e.log.Error(ErrShutdown.Error())
				defer haltedfn()
				return
			}

			// 5:A <- DB: fetch epoch state for replies to A’s א
			// 6:A -> DB: transmit one ג message for each new ב
			if err := e.sendT3Messages(); err != nil {
				e.log.Error(err.Error())
			} else {
				e.log.Debug("Sent T3 Messages successfully")
			}

			if !e.sentUpdateOK() {
				defer haltedfn()
				return
			}
			if e.shouldStop() {
				e.log.Error(ErrShutdown.Error())
				defer haltedfn()
				return
			}

			if e.processT3Messages() {
				break
			}
		} // end for loop
	default:
		e.updateChan <- ReunionUpdate{
			ExchangeID: e.ExchangeID,
			ContactID:  e.contactID,
			Error:      errors.New("unknown state error"),
		}
		return
	}

	// unreachable
}

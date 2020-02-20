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
	"crypto/sha256"
	"errors"
	"fmt"

	"github.com/katzenpost/reunion/commands"
	"github.com/katzenpost/reunion/crypto"
	"github.com/katzenpost/reunion/server"
	"github.com/ugorji/go/codec"
	"gopkg.in/op/go-logging.v1"
)

var (
	cborHandle = new(codec.CborHandle)

	// InvalidResponseErrMessage is an error used to indicate
	// that an invalid response from the Reunion server was received.
	InvalidResponseErrMessage = "invalid response received from Reunion DB"

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
	// Error contains an error or nil if no error.
	Error error
	// Serialized is the serialized Exchange state.
	Serialized []byte
	// Result is the received decrypted T1 message payload.
	Result []byte
}

// XXX fix me: ensure this struct type is a serializable form of the Exchange type.
type serializableExchange struct {
	Status      int
	ContactID   uint64
	Epoch       uint64
	Session     *crypto.Session
	SentT1      []byte
	SentT2Map   map[ExchangeHash][]byte
	SentT3Map   map[ExchangeHash][]byte
	ReceivedT2s map[ExchangeHash][]byte
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
	shutdownChan chan interface{}

	status    int
	contactID uint64
	session   *crypto.Session

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

	remoteSequence uint64
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
	updateChan chan ReunionUpdate) (*Exchange, error) {

	session, err := crypto.NewSession(passphrase, sharedRandomValue, epoch)
	if err != nil {
		return nil, err
	}
	return &Exchange{
		log:          log,
		updateChan:   updateChan,
		db:           db,
		shutdownChan: make(chan interface{}),
		status:       initialState,
		contactID:    contactID,
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

// Marshal returns a serialization of the Exchange or an error.
// XXX fix me; added many more fields since this was written...
func (e *Exchange) Marshal() ([]byte, error) {
	ex := serializableExchange{
		ContactID:   e.contactID,
		Status:      e.status,
		Session:     e.session,
		SentT1:      e.sentT1,
		SentT2Map:   e.sentT2Map,
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

func (e *Exchange) processState(state *server.RequestedReunionState) (bool, error) {
	hasNew := false

	for t1hash, t1 := range state.T1Map {
		if _, ok := e.receivedT1s[t1hash]; !ok {
			e.log.Debugf("t1 hash %x", t1hash)
			e.receivedT1s[t1hash] = t1
			hasNew = true
		}
	}
	for _, message := range state.Messages {
		if len(message.T2Payload) > 0 {
			if _, ok := e.receivedT2s[message.SrcT1Hash]; !ok {
				e.log.Debug("t2 payload")
				e.receivedT2s[message.SrcT1Hash] = message.T2Payload
				hasNew = true
			} else {
				e.log.Debugf("skipping received t2 because it's src t1 hash %x already exists in the map", message.SrcT1Hash[:])
			}
		} else if len(message.T3Payload) > 0 {
			if _, ok := e.receivedT3s[message.SrcT1Hash]; !ok {
				e.log.Debug("t3 payload")
				e.receivedT3s[message.SrcT1Hash] = message.T3Payload
				hasNew = true
			} else {
				e.log.Debug("skipping received t3 because it's src t1 hash already exists in the map")
			}
		} else {
			return false, errors.New("wtf, invalid message found")
		}
	}
	return hasNew, nil
}

func (e *Exchange) fetchState() error {
	fetchStateCmd := new(commands.FetchState)
	fetchStateCmd.Epoch = e.session.Epoch()
	h := sha256.New()
	h.Write(e.sentT1)
	t1Hash := h.Sum(nil)
	t1HashAr := [sha256.Size]byte{}
	copy(t1HashAr[:], t1Hash)
	fetchStateCmd.T1Hash = t1HashAr

	rawResponse, err := e.db.Query(fetchStateCmd, e.shutdownChan)
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

func (e *Exchange) sendT1() bool {
	var err error
	e.sentT1, err = e.session.GenerateType1Message(e.payload)
	if err != nil {
		e.log.Error(err.Error())
		return false
	}
	t1Cmd := commands.SendT1{
		Epoch:   e.session.Epoch(),
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
	hasSent := false

	h := sha256.New()
	h.Write([]byte(e.sentT1))
	myT1Hash := h.Sum(nil)
	myT1HashAr := [sha256.Size]byte{}
	copy(myT1HashAr[:], myT1Hash)

	for t1Hash, t1 := range e.receivedT1s {
		_, ok := e.repliedT1s[t1Hash]
		if ok {
			e.log.Debug("skipping previously replied")
			continue
		}

		// decrypt alpha pub key and store it in our state
		alpha, _, _, err := crypto.DecodeT1Message(t1)
		if err != nil {
			e.log.Error(err.Error())
			return false
		}
		t2, alphaPubKey, err := e.session.ProcessType1MessageAlpha(alpha)
		if err != nil {
			e.log.Error(err.Error())
			return false
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
		e.log.Debug("sending t2")
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
		e.repliedT1s[t1Hash] = t1
		hasSent = true
	}
	return hasSent
}

func (e *Exchange) sendT3Messages() bool {
	hasSentT3 := false

	e.log.Debugf("receivedT2s is size %d", len(e.receivedT2s))

	h := sha256.New()
	h.Write([]byte(e.sentT1))
	myT1Hash := h.Sum(nil)
	myT1HashAr := [sha256.Size]byte{}
	copy(myT1HashAr[:], myT1Hash)

	for srcT1Hash, t2 := range e.receivedT2s {
		e.log.Debug("for each t2")

		t1, ok := e.receivedT1s[srcT1Hash]
		if !ok {
			e.log.Errorf("error yo, t1 hash %x missing from map", srcT1Hash[:])
			return false
		}

		h := sha256.New()
		h.Write(t2)
		t2Hash := h.Sum(nil)
		t2HashAr := [sha256.Size]byte{}
		copy(t2HashAr[:], t2Hash)

		if _, ok := e.repliedT2s[t2HashAr]; ok {
			e.log.Debug("skipping sent t2hash")
			continue
		}

		alphaKey, ok := e.receivedT1Alphas[srcT1Hash]
		if !ok {
			e.log.Errorf("src t1 hash not found in received t1 alphas map")
			return false
		}
		candidateKey, err := e.session.GetCandidateKey(t2, alphaKey)
		if err != nil {
			e.log.Error(err.Error())
			return false
		}

		_, t1beta, _, err := crypto.DecodeT1Message(t1)
		if err != nil {
			e.log.Error(err.Error())
			return false
		}
		beta, err := crypto.DecryptT1Beta(candidateKey, t1beta)
		if err != nil {
			e.log.Error(err.Error())
			continue
		}
		t3, err := e.session.ComposeType3Message(beta)
		if err != nil {
			e.log.Error(err.Error())
			return false
		}
		sendT3Cmd := commands.SendT3{
			Epoch:     e.session.Epoch(),
			T2Hash:    t2HashAr,
			SrcT1Hash: myT1HashAr,
			DstT1Hash: srcT1Hash,
			Payload:   t3,
		}
		e.log.Debug("before sending sendT3 command to reunion DB")
		rawResponse, err := e.db.Query(&sendT3Cmd, e.shutdownChan)
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

		e.decryptedT1Betas[srcT1Hash] = beta
		hasSentT3 = true

		e.repliedT2s[t2HashAr] = t2
	}

	return hasSentT3
}

func (e *Exchange) processT3Messages() bool {
	e.log.Debugf("processT3Messages %d t3s", len(e.receivedT3s))

	for srcT1Hash, t3 := range e.receivedT3s {
		e.log.Debug("for each t3")

		beta, ok := e.decryptedT1Betas[srcT1Hash]
		if !ok {
			e.log.Debug("src t1 hash not found in decrypted t1 beta map")
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
			e.log.Debug("ProcessType3Message failure")
			return false
		}
		e.updateChan <- ReunionUpdate{
			ContactID:  e.contactID,
			Error:      nil,
			Serialized: nil,
			Result:     plaintext,
		}
		e.log.Debug("true")
		return true
	}
	e.log.Debug("false")
	return false
}

// Run performs the Reunion exchange and expresses a simple
// FSM which uses the updateChan to save it's state after each
// state transition. This method is meant to run in it's own
// goroutine.
func (e *Exchange) Run() {
	defer e.log.Debug("Run was halted.")
	switch e.status {
	case initialState:
		// XXX not required -> 1:A <- DB: fetch current epoch and current set of data for epoch state
		// 2:A -> DB: transmit א message
		e.log.Debug("sending T1 message")
		if !e.sendT1() {
			return
		}
		e.status = t1MessageSentState
		if !e.sentUpdateOK() {
			return
		}
		if e.shouldStop() {
			e.log.Error(ErrShutdown.Error())
			return
		}
		fallthrough
	case t1MessageSentState:
		e.log.Debug("Entered T1 Sent State")
		for {
			// 3:A <- DB: fetch epoch state
			e.log.Debug("fetching state")
			err := e.fetchState()
			if err != nil {
				e.log.Error(err.Error())
				return
			}
			// 4:A -> DB: transmit one ב message for each א
			e.log.Debug("maybe send T2 messages")
			e.sendT2Messages()
			if !e.sentUpdateOK() {
				return
			}
			if e.shouldStop() {
				e.log.Error(ErrShutdown.Error())
				return
			}

			// 5:A <- DB: fetch epoch state for replies to A’s א
			// 6:A -> DB: transmit one ג message for each new ב
			e.log.Debug("maybe send T3 messages")
			e.sendT3Messages()

			if !e.sentUpdateOK() {
				return
			}
			if e.shouldStop() {
				e.log.Error(ErrShutdown.Error())
				return
			}

			e.log.Debug("before process T3 messages")
			if e.processT3Messages() {
				e.log.Debug("OK")
				break
			}
			e.log.Debug("!OK")

		} // end for loop
	default:
		e.updateChan <- ReunionUpdate{
			ContactID: e.contactID,
			Error:     errors.New("unknown state"),
		}
		return
	}

	// unreachable
}

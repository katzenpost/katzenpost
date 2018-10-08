// send.go - mixnet client send
// Copyright (C) 2018  David Stainton.
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

package session

import (
	"fmt"
	"io"
	"sync"
	"time"

	cConstants "github.com/katzenpost/client/constants"
	"github.com/katzenpost/core/constants"
	"github.com/katzenpost/core/crypto/rand"
	sConstants "github.com/katzenpost/core/sphinx/constants"
)

// MessageRef is a message reference which is used to match future
// received SURN replies.
type MessageRef struct {
	// ID is the message identifier
	ID *[cConstants.MessageIDLength]byte

	// Recipient is the message recipient
	Recipient string

	// Provider is the recipient Provider
	Provider string

	// Payload is the message payload
	Payload []byte

	// SentAt contains the time the message was sent.
	SentAt time.Time

	// ReplyETA is the expected round trip time to receive a response.
	ReplyETA time.Duration

	// WithSURB is set to true if a message is sent with a SURB.
	WithSURB bool

	// SURBID is the SURB identifier.
	SURBID *[sConstants.SURBIDLength]byte

	// Key is the SURB decryption keys
	Key []byte

	// Reply is the SURB reply
	Reply []byte

	// SURBType is the SURB type.
	SURBType int
}

// WaitForReply blocks until a reply is received.
func (s *Session) WaitForReply(msgRef *MessageRef) []byte {
	s.mapLock.Lock()
	replyLock := s.replyNotifyMap[*msgRef.ID]
	s.mapLock.Unlock()
	replyLock.Lock()
	return s.messageIDMap[*msgRef.ID].Reply
}

func (s *Session) sendNext() error {
	s.egressQueueLock.Lock()
	defer s.egressQueueLock.Unlock()

	msgRef, err := s.egressQueue.Peek()
	if err != nil {
		return err
	}
	if msgRef.Provider == "" {
		panic("wtf")
	}
	err = s.send(msgRef)
	if err != nil {
		return err
	}
	_, err = s.egressQueue.Pop()
	return err
}

func (s *Session) send(msgRef *MessageRef) error {
	var err error
	if msgRef.WithSURB {
		surbID := [sConstants.SURBIDLength]byte{}
		io.ReadFull(rand.Reader, surbID[:])
		key, eta, err := s.minclient.SendCiphertext(msgRef.Recipient, msgRef.Provider, &surbID, msgRef.Payload)
		if err != nil {
			return err
		}
		msgRef.Key = key
		msgRef.SentAt = time.Now()
		msgRef.ReplyETA = eta

		s.mapLock.Lock()
		defer s.mapLock.Unlock()

		s.surbIDMap[surbID] = msgRef
		s.messageIDMap[*msgRef.ID] = msgRef
	} else {
		err = s.minclient.SendUnreliableCiphertext(msgRef.Recipient, msgRef.Provider, msgRef.Payload)
	}
	return err
}

func (s *Session) sendDropDecoy() error {
	s.log.Info("sending drop decoy")
	return s.sendLoop(false)
}

func (s *Session) sendLoopDecoy() error {
	s.log.Info("sending loop decoy")
	return s.sendLoop(true)
}

func (s *Session) sendLoop(withSURB bool) error {
	const loopService = "loop"
	serviceDesc, err := s.GetService(loopService)
	if err != nil {
		return err
	}
	payload := [constants.UserForwardPayloadLength]byte{}
	id := [cConstants.MessageIDLength]byte{}
	io.ReadFull(rand.Reader, id[:])
	msgRef := &MessageRef{
		ID:        &id,
		Recipient: serviceDesc.Name,
		Provider:  serviceDesc.Provider,
		Payload:   payload[:],
		WithSURB:  withSURB,
	}
	return s.send(msgRef)
}

// SendUnreliable send a message without any automatic retransmission.
func (s *Session) SendUnreliable(recipient, provider string, message []byte) (*MessageRef, error) {
	s.log.Debugf("Send")
	id := [cConstants.MessageIDLength]byte{}
	io.ReadFull(rand.Reader, id[:])
	var msgRef = MessageRef{
		ID:        &id,
		Recipient: recipient,
		Provider:  provider,
		Payload:   message,
		WithSURB:  false,
	}

	s.egressQueueLock.Lock()
	defer s.egressQueueLock.Unlock()

	err := s.egressQueue.Push(&msgRef)
	return &msgRef, err
}

// SendKaetzchenQuery sends a mixnet provider-side service query.
func (s *Session) SendKaetzchenQuery(recipient, provider string, message []byte, wantResponse bool) (*MessageRef, error) {
	if provider == "" {
		panic("wtf")
	}
	// Ensure the request message is under the maximum for a single
	// packet, and pad out the message so that it is the correct size.
	if len(message) > constants.UserForwardPayloadLength {
		return nil, fmt.Errorf("invalid message size: %v", len(message))
	}
	payload := make([]byte, constants.UserForwardPayloadLength)
	copy(payload, message)
	id := [cConstants.MessageIDLength]byte{}
	io.ReadFull(rand.Reader, id[:])
	var msgRef = MessageRef{
		ID:        &id,
		Recipient: recipient,
		Provider:  provider,
		Payload:   payload,
		WithSURB:  wantResponse,
		SURBType:  cConstants.SurbTypeKaetzchen,
	}

	s.mapLock.Lock()
	defer s.mapLock.Unlock()

	s.replyNotifyMap[*msgRef.ID] = new(sync.Mutex)
	s.replyNotifyMap[*msgRef.ID].Lock()

	s.egressQueueLock.Lock()
	defer s.egressQueueLock.Unlock()

	err := s.egressQueue.Push(&msgRef)
	return &msgRef, err
}

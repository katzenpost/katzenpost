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

// Message is a message reference which is used to match future
// received SURB replies.
type Message struct {
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
func (s *Session) WaitForReply(msgId *[cConstants.MessageIDLength]byte) []byte {
	s.log.Debugf("WaitForReply message ID: %x\n", *msgId)
	s.mapLock.Lock()
	replyLock := s.replyNotifyMap[*msgId]
	s.mapLock.Unlock()
	replyLock.Lock()
	s.mapLock.Lock()
	defer s.mapLock.Unlock()
	return s.messageIDMap[*msgId].Reply
}

func (s *Session) sendNext() error {
	s.egressQueueLock.Lock()
	defer s.egressQueueLock.Unlock()

	msg, err := s.egressQueue.Peek()
	if err != nil {
		return err
	}
	if msg.Provider == "" {
		panic("Provider cannot be empty string")
	}
	err = s.doSend(msg)
	if err != nil {
		return err
	}
	_, err = s.egressQueue.Pop()
	return err
}

func (s *Session) doSend(msg *Message) error {
	surbID := [sConstants.SURBIDLength]byte{}
	io.ReadFull(rand.Reader, surbID[:])
	key, eta, err := s.minclient.SendCiphertext(msg.Recipient, msg.Provider, &surbID, msg.Payload)
	if err != nil {
		return err
	}
	msg.Key = key
	msg.SentAt = time.Now()
	msg.ReplyETA = eta
	s.mapLock.Lock()
	defer s.mapLock.Unlock()
	s.surbIDMap[surbID] = msg
	return err
}

func (s *Session) sendLoopDecoy() error {
	s.log.Info("sending loop decoy")
	const loopService = "loop"
	serviceDesc, err := s.GetService(loopService)
	if err != nil {
		return err
	}
	payload := [constants.UserForwardPayloadLength]byte{}
	id := [cConstants.MessageIDLength]byte{}
	io.ReadFull(rand.Reader, id[:])
	msg := &Message{
		ID:        &id,
		Recipient: serviceDesc.Name,
		Provider:  serviceDesc.Provider,
		Payload:   payload[:],
	}
	return s.doSend(msg)
}

func (s *Session) composeMessage(recipient, provider string, message []byte, query bool) (*Message, error) {
	s.log.Debug("SendMessage")
	if len(message) > constants.UserForwardPayloadLength {
		return nil, fmt.Errorf("invalid message size: %v", len(message))
	}
	payload := make([]byte, constants.UserForwardPayloadLength)
	copy(payload, message)
	id := [cConstants.MessageIDLength]byte{}
	io.ReadFull(rand.Reader, id[:])
	var msg = Message{
		ID:        &id,
		Recipient: recipient,
		Provider:  provider,
		Payload:   payload,
	}
	if query {
		msg.SURBType = cConstants.SurbTypeKaetzchen
	} else {
		msg.SURBType = cConstants.SurbTypeACK
	}
	return &msg, nil
}

// SendQuery sends a mixnet provider-side service query.
func (s *Session) SendUnreliableQuery(recipient, provider string, message []byte) (*[cConstants.MessageIDLength]byte, error) {
	msg, err := s.composeMessage(recipient, provider, message, true)
	if err != nil {
		return nil, err
	}

	s.mapLock.Lock()
	s.replyNotifyMap[*msg.ID] = new(sync.Mutex)
	s.replyNotifyMap[*msg.ID].Lock()
	s.messageIDMap[*msg.ID] = msg
	s.mapLock.Unlock()

	s.egressQueueLock.Lock()
	defer s.egressQueueLock.Unlock()
	err = s.egressQueue.Push(msg)
	if err != nil {
		return nil, err
	}
	return msg.ID, err
}

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

type MessageRef struct {
	ID        *[cConstants.MessageIDLength]byte
	Recipient string
	Provider  string
	Payload   []byte
	SentAt    time.Time
	ReplyETA  time.Duration
	WithSURB  bool
	SURBID    *[sConstants.SURBIDLength]byte
	Key       []byte
	Reply     []byte
	SURBType  int
}

// WaitForReply blocks until a reply is received.
func (s *Session) WaitForReply(msgRef *MessageRef) []byte {
	s.replyNotifyMap[*msgRef.ID].Lock()
	return s.messageIDMap[*msgRef.ID].Reply
}

func (s *Session) sendNext() error {
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
	err := s.egressQueue.Push(&msgRef)
	return &msgRef, err
}

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
		SURBType:  surbTypeKaetzchen,
	}
	s.replyNotifyMap[*msgRef.ID] = new(sync.Mutex)
	s.replyNotifyMap[*msgRef.ID].Lock()
	err := s.egressQueue.Push(&msgRef)
	return &msgRef, err
}

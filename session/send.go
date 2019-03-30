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
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"time"

	cConstants "github.com/katzenpost/client/constants"
	"github.com/katzenpost/core/constants"
	"github.com/katzenpost/core/crypto/rand"
	sConstants "github.com/katzenpost/core/sphinx/constants"
)

const roundTripTimeSlop = time.Duration(88 * time.Second)

// WaitForSent blocks until the message with the corresponding message ID is sent.
func (s *Session) WaitForSent(id MessageID) error {
	s.log.Debug("Waiting for message to be sent.")
	var waitCh chan Event
	var err error
	s.mapLock.Lock()
	msg, ok := s.messageIDMap[*id]
	if !ok {
		err = fmt.Errorf("[%v] Failure waiting for reply, invalid message ID", id)
	} else {
		if msg.Sent {
			return nil
		}
	}
	waitCh, ok = s.waitSentChans[*id]
	if ok {
		defer delete(s.waitSentChans, *id)
	} else {
		err = fmt.Errorf("[%v] Failure waiting for reply, invalid message ID", id)
	}
	s.mapLock.Unlock()
	if err != nil {
		return err
	}
	select {
	case <-waitCh:
	case <-time.After(1 * time.Minute):
		return fmt.Errorf("[%v] Failure waiting for reply, timeout", id)
	}
	s.log.Debug("Finished waiting. Message was sent.")
	return nil
}

// WaitForReply blocks until a reply is received.
func (s *Session) WaitForReply(id MessageID) ([]byte, error) {
	s.log.Debugf("WaitForReply message ID: %x\n", *id)
	err := s.WaitForSent(id)
	if err != nil {
		return nil, err
	}
	s.mapLock.Lock()
	waitCh, ok := s.waitChans[*id]
	if ok {
		defer delete(s.waitChans, *id)
	} else {
		err = fmt.Errorf("[%v] Failure waiting for reply, invalid message ID", id)
	}
	msg, ok := s.messageIDMap[*id]
	if ok {
		// XXX Consider what will happen because of this deletion
		// when we implement an ARQ based reliability.
		defer delete(s.messageIDMap, *id)
	} else {
		err = fmt.Errorf("[%v] Failure waiting for reply, invalid message ID", id)
	}
	s.log.Debug("reply eta is %v", msg.ReplyETA)
	s.mapLock.Unlock()
	if err != nil {
		return nil, err
	}
	select {
	case event := <-waitCh:
		e, ok := event.(*MessageReplyEvent)
		if !ok {
			s.log.Debug("UNKNOWN EVENT TYPE FOUND IN WAIT CHANNEL FOR THE GIVEN MESSAGE ID.")
		}
		return e.Payload, nil
	case <-time.After(msg.ReplyETA + roundTripTimeSlop):
		return nil, fmt.Errorf("[%v] Failure waiting for reply, timeout reached", id)
	}
	// unreachable
}

func (s *Session) sendNext() error {
	msg, err := s.egressQueue.Peek()
	if err != nil {
		return err
	}
	if msg == nil {
		return errors.New("send next failure, message is nil")
	}
	m, ok := msg.(*Message)
	if !ok {
		return errors.New("send next failure, unknown message type")
	}
	err = s.doSend(m)
	if err != nil {
		return err
	}
	_, err = s.egressQueue.Pop()
	return err
}

func (s *Session) doSend(msg *Message) error {
	surbID := [sConstants.SURBIDLength]byte{}
	_, err := io.ReadFull(rand.Reader, surbID[:])
	if err != nil {
		return err
	}
	idStr := fmt.Sprintf("[%v]", hex.EncodeToString(surbID[:]))
	s.log.Debugf("doSend with SURB ID %x", idStr)
	key := []byte{}
	var eta time.Duration
	if msg.WithSURB {
		key, eta, err = s.minclient.SendCiphertext(msg.Recipient, msg.Provider, &surbID, msg.Payload)
	} else {
		err = s.minclient.SendUnreliableCiphertext(msg.Recipient, msg.Provider, msg.Payload)
	}
	if err != nil {
		return err
	}
	if msg.WithSURB {
		s.log.Debugf("doSend setting ReplyETA to %v", eta)
		msg.Key = key
		msg.SentAt = time.Now()
		msg.Sent = true
		msg.ReplyETA = eta
		s.mapLock.Lock()
		s.surbIDMap[surbID] = msg
		s.mapLock.Unlock()
	}

	eventCh, ok := s.waitSentChans[*msg.ID]
	if ok {
		select {
		case eventCh <- &MessageSentEvent{
			MessageID: msg.ID,
			Err:       nil,
		}:
		case <-time.After(3 * time.Second):
			s.log.Debug("timeout reached when attempting to sent to waitSentChans")
			break
		}
	} else {
		s.log.Debug("no waitSentChans map entry found for that message ID")
	}
	return nil
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
	_, err = io.ReadFull(rand.Reader, id[:])
	if err != nil {
		return err
	}
	msg := &Message{
		ID:        &id,
		Recipient: serviceDesc.Name,
		Provider:  serviceDesc.Provider,
		Payload:   payload[:],
		WithSURB:  true,
		IsDecoy:   true,
	}
	defer s.incrementDecoyLoopTally()
	return s.doSend(msg)
}

func (s *Session) sendDropDecoy() error {
	s.log.Info("sending drop decoy")
	const loopService = "loop"
	serviceDesc, err := s.GetService(loopService)
	if err != nil {
		return err
	}
	payload := [constants.UserForwardPayloadLength]byte{}
	id := [cConstants.MessageIDLength]byte{}
	_, err = io.ReadFull(rand.Reader, id[:])
	if err != nil {
		return err
	}
	msg := &Message{
		ID:        &id,
		Recipient: serviceDesc.Name,
		Provider:  serviceDesc.Provider,
		Payload:   payload[:],
		WithSURB:  false,
		IsDecoy:   true,
	}
	return s.doSend(msg)
}

func (s *Session) composeMessage(recipient, provider string, message []byte) (*Message, error) {
	s.log.Debug("SendMessage")
	if len(message) > constants.UserForwardPayloadLength {
		return nil, fmt.Errorf("invalid message size: %v", len(message))
	}
	payload := make([]byte, constants.UserForwardPayloadLength)
	copy(payload, message)
	id := [cConstants.MessageIDLength]byte{}
	_, err := io.ReadFull(rand.Reader, id[:])
	if err != nil {
		return nil, err
	}
	var msg = Message{
		ID:        &id,
		Recipient: recipient,
		Provider:  provider,
		Payload:   payload,
		WithSURB:  true,
	}
	msg.SURBType = cConstants.SurbTypeKaetzchen
	return &msg, nil
}

// SendUnreliableMessage sends message without any automatic retransmissions.
func (s *Session) SendUnreliableMessage(recipient, provider string, message []byte) (*[cConstants.MessageIDLength]byte, error) {
	msg, err := s.composeMessage(recipient, provider, message)
	if err != nil {
		return nil, err
	}

	s.mapLock.Lock()
	s.messageIDMap[*msg.ID] = msg
	s.waitChans[*msg.ID] = make(chan Event)
	s.waitSentChans[*msg.ID] = make(chan Event)
	s.mapLock.Unlock()

	err = s.egressQueue.Push(msg)
	if err != nil {
		return nil, err
	}
	return msg.ID, err
}

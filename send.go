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

package client

import (
	"encoding/binary"
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

var ErrReplyTimeout = errors.New("failure waiting for reply, timeout reached")

func (s *Session) sendNext() {
	msg, err := s.egressQueue.Peek()
	if err != nil {
		err := errors.New("impossible failure to Peek from queue")
		s.log.Error(err.Error())
		s.fatalErrCh <- err
		return
	}
	if msg == nil {
		err := errors.New("impossible failure, got nil message from queue")
		s.log.Error(err.Error())
		s.fatalErrCh <- err
		return
	}
	m := msg.(*Message)
	s.doSend(m)
	_, err = s.egressQueue.Pop()
	if err != nil {
		err := errors.New("impossible failure to Pop from queue")
		s.log.Error(err.Error())
		s.fatalErrCh <- err
	}
}

func (s *Session) doSend(msg *Message) {
	surbID := [sConstants.SURBIDLength]byte{}
	_, err := io.ReadFull(rand.Reader, surbID[:])
	if err != nil {
		err := fmt.Errorf("impossible failure, failed to generate SURB ID for message ID %x", *msg.ID)
		s.log.Error(err.Error())
		s.fatalErrCh <- err
		return
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
	if msg.WithSURB {
		s.log.Debugf("doSend setting ReplyETA to %v", eta)
		msg.Key = key
		msg.SentAt = time.Now()
		msg.ReplyETA = eta
		s.surbIDMap.Store(surbID, msg)
	}
	if msg.IsBlocking {
		sentWaitChanRaw, ok := s.sentWaitChanMap.Load(*msg.ID)
		if !ok {
			err := fmt.Errorf("impossible failure, sentWaitChan not found for message ID %x", *msg.ID)
			s.log.Error(err.Error())
			s.fatalErrCh <- err
			return
		}
		sentWaitChan := sentWaitChanRaw.(chan *Message)
		sentWaitChan <- msg
	} else {
		s.eventCh.In() <- &MessageSentEvent{
			MessageID: msg.ID,
			Err:       err,
			SentAt:    msg.SentAt,
			ReplyETA:  msg.ReplyETA,
		}
	}
}

func (s *Session) sendLoopDecoy() {
	s.log.Info("sending loop decoy")
	const loopService = "loop"
	serviceDesc, err := s.GetService(loopService)
	if err != nil {
		err := errors.New("failure to get loop service")
		s.log.Error(err.Error())
		s.fatalErrCh <- err
		return
	}
	payload := [constants.UserForwardPayloadLength]byte{}
	id := [cConstants.MessageIDLength]byte{}
	_, err = io.ReadFull(rand.Reader, id[:])
	if err != nil {
		err := errors.New("failure to generate message ID for loop decoy")
		s.log.Error(err.Error())
		s.fatalErrCh <- err
		return
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
	s.doSend(msg)
}

func (s *Session) composeMessage(recipient, provider string, message []byte, isBlocking bool) (*Message, error) {
	s.log.Debug("SendMessage")
	if len(message) > constants.UserForwardPayloadLength-4 {
		return nil, fmt.Errorf("invalid message size: %v", len(message))
	}
	payload := [constants.UserForwardPayloadLength]byte{}
	binary.BigEndian.PutUint32(payload[:4], uint32(len(message)))
	copy(payload[4:], message)
	id := [cConstants.MessageIDLength]byte{}
	_, err := io.ReadFull(rand.Reader, id[:])
	if err != nil {
		return nil, err
	}
	var msg = Message{
		ID:         &id,
		Recipient:  recipient,
		Provider:   provider,
		Payload:    payload[:],
		WithSURB:   true,
		IsBlocking: isBlocking,
	}
	return &msg, nil
}

// SendUnreliableMessage asynchronously sends message without any automatic retransmissions.
func (s *Session) SendUnreliableMessage(recipient, provider string, message []byte) (MessageID, error) {
	msg, err := s.composeMessage(recipient, provider, message, false)
	if err != nil {
		return nil, err
	}
	err = s.egressQueue.Push(msg)
	if err != nil {
		return nil, err
	}
	return msg.ID, nil
}

func (s *Session) BlockingSendUnreliableMessage(recipient, provider string, message []byte) ([]byte, error) {
	msg, err := s.composeMessage(recipient, provider, message, true)
	if err != nil {
		return nil, err
	}
	sentWaitChan := make(chan *Message)
	s.sentWaitChanMap.Store(*msg.ID, sentWaitChan)
	defer s.sentWaitChanMap.Delete(*msg.ID)

	replyWaitChan := make(chan []byte)
	s.replyWaitChanMap.Store(*msg.ID, replyWaitChan)
	defer s.replyWaitChanMap.Delete(*msg.ID)

	err = s.egressQueue.Push(msg)
	if err != nil {
		return nil, err
	}

	// wait until sent so that we know the ReplyETA for the waiting below
	sentMessage := <-sentWaitChan

	// wait for reply or round trip timeout
	select {
	case reply := <-replyWaitChan:
		return reply, nil
	case <-time.After(sentMessage.ReplyETA + cConstants.RoundTripTimeSlop):
		return nil, ErrReplyTimeout
	}
	// unreachable
}

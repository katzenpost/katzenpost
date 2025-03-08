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
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/katzenpost/hpqc/rand"

	cConstants "github.com/katzenpost/katzenpost/client/constants"
	"github.com/katzenpost/katzenpost/client/utils"
	sConstants "github.com/katzenpost/katzenpost/core/sphinx/constants"
)

var ErrReplyTimeout = errors.New("failure waiting for reply, timeout reached")
var ErrHalted = errors.New("Halted")
var ErrMessageNotSent = errors.New("failure sending message")

func (s *Session) sendNext() {
	msg, err := s.egressQueue.Peek()
	if err != nil {
		s.fatalErrCh <- errors.New("impossible failure to Peek from queue")
		return
	}
	if msg == nil {
		s.fatalErrCh <- errors.New("impossible failure, got nil message from queue")
		return
	}
	m := msg.(*Message)
	s.doSend(m)
	_, err = s.egressQueue.Pop()
	if err != nil {
		s.fatalErrCh <- errors.New("impossible failure to Pop from queue")
	}
}

func (s *Session) doRetransmit(msg *Message) {
	msg.Retransmissions++
	msgIdStr := fmt.Sprintf("[%v]", hex.EncodeToString(msg.ID[:]))
	s.log.Debugf("doRetransmit: %d for %s", msg.Retransmissions, msgIdStr)
	s.egressQueue.Push(msg)
}

func (s *Session) doSend(msg *Message) {

	surbID := [sConstants.SURBIDLength]byte{}
	_, err := io.ReadFull(rand.Reader, surbID[:])
	if err != nil {
		s.fatalErrCh <- fmt.Errorf("impossible failure, failed to generate SURB ID for message ID %x", *msg.ID)
		return
	}
	key := []byte{}
	var eta time.Duration
	msgIdStr := fmt.Sprintf("[%v]", hex.EncodeToString(msg.ID[:]))
	if msg.WithSURB {
		msg.SURBID = &surbID
		surbIdStr := fmt.Sprintf("[%v]", hex.EncodeToString(surbID[:]))
		s.log.Debugf("doSend %s with SURB ID %s", msgIdStr, surbIdStr)
		key, eta, err = s.minclient.SendCiphertext(msg.Recipient, msg.Provider, &surbID, msg.Payload)
		if err != nil {
			s.log.Debugf("SendCiphertext failed with error: %s", err)
		}
	} else {
		s.log.Debugf("doSend %s without SURB", msgIdStr)
		err = s.minclient.SendUnreliableCiphertext(msg.Recipient, msg.Provider, msg.Payload)
		if err != nil {
			s.log.Debugf("SendUnreliableCiphertext failed with error: %s", err)
		}
	}
	// message was sent
	if err == nil {
		msg.SentAt = time.Now()
	}
	// expect a reply
	if msg.WithSURB {
		if err == nil {
			s.log.Debugf("doSend setting ReplyETA to %v", eta)
			// increase the timeout for each retransmission
			msg.ReplyETA = eta * (1 + time.Duration(msg.Retransmissions))
			msg.Key = key
			s.surbIDMap.Store(surbID, msg)
			if msg.Reliable {
				s.log.Debugf("Sending reliable message with retransmissions")
				timeSlop := eta // add a round-trip worth of delay before timing out
				msg.SetPriority(uint64(msg.SentAt.Add(msg.ReplyETA).Add(timeSlop).UnixNano()))
				s.timerQ.Push(msg)
			}
		}
		// write to waiting channel or close channel if message failed to send
		if msg.IsBlocking {
			sentWaitChanRaw, ok := s.sentWaitChanMap.Load(*msg.ID)
			if !ok {
				return
			}
			sentWaitChan := sentWaitChanRaw.(chan *Message)
			if err == nil {
				// do not block writing to the receiver if this is a retransmission
				select {
				case sentWaitChan <- msg:
				default:
				}

			} else {
				close(sentWaitChan)
			}
			return
		}
	}
	s.eventCh <- &MessageSentEvent{
		MessageID: msg.ID,
		Err:       err,
		SentAt:    msg.SentAt,
		ReplyETA:  msg.ReplyETA,
	}
}

func (s *Session) sendDropDecoy(loopSvc *utils.ServiceDescriptor) {
	payload := make([]byte, s.geo.UserForwardPayloadLength)
	id := [cConstants.MessageIDLength]byte{}
	_, err := io.ReadFull(rand.Reader, id[:])
	if err != nil {
		s.fatalErrCh <- errors.New("failure to generate message ID for drop decoy")
		return
	}
	msg := &Message{
		ID:        &id,
		Recipient: loopSvc.Name,
		Provider:  loopSvc.Provider,
		Payload:   payload[:],
		WithSURB:  false,
		IsDecoy:   true,
	}
	s.doSend(msg)
}

func (s *Session) sendLoopDecoy(loopSvc *utils.ServiceDescriptor) {
	s.log.Info("sending loop decoy")
	payload := make([]byte, s.geo.UserForwardPayloadLength)
	id := [cConstants.MessageIDLength]byte{}
	_, err := io.ReadFull(rand.Reader, id[:])
	if err != nil {
		s.fatalErrCh <- errors.New("failure to generate message ID for loop decoy")
		return
	}
	msg := &Message{
		ID:        &id,
		Recipient: loopSvc.Name,
		Provider:  loopSvc.Provider,
		Payload:   payload[:],
		WithSURB:  true,
		IsDecoy:   true,
	}
	defer s.incrementDecoyLoopTally()
	s.doSend(msg)
}

func (s *Session) composeMessage(recipient, provider string, message []byte, isBlocking bool) (*Message, error) {
	s.log.Debug("SendMessage")
	if len(message) > s.geo.UserForwardPayloadLength {
		return nil, fmt.Errorf("message too large: %v > %v", len(message), s.geo.UserForwardPayloadLength)
	}
	payload := make([]byte, s.geo.UserForwardPayloadLength)
	copy(payload, message)
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

// SendReliableMessage asynchronously sends messages with automatic retransmissiosn.
func (s *Session) SendReliableMessage(recipient, provider string, message []byte) (*[cConstants.MessageIDLength]byte, error) {
	msg, err := s.composeMessage(recipient, provider, message, false)
	if err != nil {
		return nil, err
	}
	msg.Reliable = true
	err = s.egressQueue.Push(msg)
	if err != nil {
		return nil, err
	}
	return msg.ID, nil
}

// SendUnreliableMessage asynchronously sends message without any automatic retransmissions.
func (s *Session) SendUnreliableMessage(recipient, provider string, message []byte) (*[cConstants.MessageIDLength]byte, error) {
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
	return s.BlockingSendUnreliableMessageWithContext(nil, recipient, provider, message)
}

func (s *Session) BlockingSendUnreliableMessageWithContext(ctx context.Context, recipient, provider string, message []byte) ([]byte, error) {
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
	select {
	case sentMessage := <-sentWaitChan:
		// if the message failed to send we will receive a nil message
		if sentMessage == nil {
			return nil, ErrMessageNotSent
		}
		// use a default context with the estimated replyETA if one is not specified
		var cancelFn func()
		if ctx == nil {
			ctx, cancelFn = context.WithTimeout(context.Background(), sentMessage.ReplyETA+cConstants.RoundTripTimeSlop)
			defer cancelFn()
		}
	case <-s.HaltCh():
		return nil, ErrHalted
	}

	// wait for reply or round trip timeout
	select {
	case reply := <-replyWaitChan:
		return reply, nil
	case <-s.HaltCh():
		return nil, ErrHalted
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	// unreachable
}

// BlockingSendReliableMessage sends a message with automatic message retransmission enabled
func (s *Session) BlockingSendReliableMessage(recipient, provider string, message []byte) ([]byte, error) {
	msg, err := s.composeMessage(recipient, provider, message, true)
	if err != nil {
		return nil, err
	}
	msg.Reliable = true
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

	// if the message failed to send we will receive a nil message
	if sentMessage == nil {
		return nil, ErrMessageNotSent
	}

	// XXX: may block forever
	select {
	case reply := <-replyWaitChan:
		return reply, nil
	case <-s.HaltCh():
		return nil, ErrHalted
	}
	// unreachable
}

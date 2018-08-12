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
	ACK       bool // XXX not yet used
}

// WaitForReply blocks until a reply is received.
func (c *Client) WaitForReply(msgRef *MessageRef) {
	c.replyNotifyMap[*msgRef.ID].Lock()
}

func (c *Client) sendNext() error {
	item, err := c.egressQueue.Peek()
	if err != nil {
		return err
	}
	msgRef := new(MessageRef)
	err = item.ToObject(msgRef)
	if err != nil {
		return err
	}
	err = c.send(msgRef)
	if err != nil {
		return err
	}
	_, err = c.egressQueue.Dequeue()
	return err
}

func (c *Client) send(msgRef *MessageRef) error {
	var err error
	if msgRef.WithSURB {
		surbID := [sConstants.SURBIDLength]byte{}
		io.ReadFull(rand.Reader, surbID[:])
		key, eta, err := c.minclient.SendCiphertext(msgRef.Recipient, msgRef.Provider, &surbID, msgRef.Payload)
		if err != nil {
			return err
		}
		msgRef.Key = key
		msgRef.SentAt = time.Now()
		msgRef.ReplyETA = eta
		c.surbIDMap[surbID] = msgRef
		c.messageIDMap[*msgRef.ID] = msgRef
		c.log.Infof("SENT MESSAGE ID %x", *msgRef.ID)
	} else {
		err = c.minclient.SendUnreliableCiphertext(msgRef.Recipient, msgRef.Provider, msgRef.Payload)
	}
	return err
}

func (c *Client) sendDropDecoy() error {
	c.log.Info("sending drop decoy")
	return c.sendLoop(false)
}

func (c *Client) sendLoopDecoy() error {
	c.log.Info("sending loop decoy")
	return c.sendLoop(true)
}

func (c *Client) sendLoop(withSURB bool) error {
	const loopService = "loop"
	serviceDesc, err := c.GetService(loopService)
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
	return c.send(msgRef)
}

func (c *Client) SendUnreliable(recipient, provider string, message []byte) (*MessageRef, error) {
	c.log.Debugf("Send")
	id := [cConstants.MessageIDLength]byte{}
	io.ReadFull(rand.Reader, id[:])
	var msgRef = MessageRef{
		ID:        &id,
		Recipient: recipient,
		Provider:  provider,
		Payload:   message,
		WithSURB:  false,
	}
	_, err := c.egressQueue.EnqueueObject(msgRef)
	return &msgRef, err
}

func (c *Client) SendKaetzchenQuery(recipient, provider string, message []byte, wantResponse bool) (*MessageRef, error) {
	c.log.Info("SEND KAETZCHEN QUERY")

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
	}
	c.log.Info("-----------------------------------------------------------")
	c.log.Infof("Storing reply notification mutex at message ID %x", id)
	c.replyNotifyMap[*msgRef.ID] = new(sync.Mutex)
	c.replyNotifyMap[*msgRef.ID].Lock()

	_, err := c.egressQueue.EnqueueObject(msgRef)
	return &msgRef, err
}

// send.go - mixnet client send
// Copyright (C) 2018  David Stainton, Yawning Angel.
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

	"github.com/katzenpost/core/constants"
	"github.com/katzenpost/core/crypto/rand"
	sConstants "github.com/katzenpost/core/sphinx/constants"
)

func (c *Client) sendNext() error {
	item, err := c.egressQueue.Dequeue()
	if err != nil {
		return err
	}
	manifest := new(messageManifest)
	err = item.ToObject(manifest)
	if err != nil {
		return err
	}
	return c.send(manifest)
}

func (c *Client) send(manifest *messageManifest) error {
	var err error
	if manifest.WithSURB {
		surbID := [sConstants.SURBIDLength]byte{}
		io.ReadFull(rand.Reader, surbID[:])
		key, eta, err := c.minclient.SendCiphertext(manifest.Recipient, manifest.Provider, &surbID, manifest.Message)
		if err != nil {
			return err
		}
		c.surbKeys[surbID] = key
		c.surbEtas[eta] = surbID

	} else {
		err = c.minclient.SendUnreliableCiphertext(manifest.Recipient, manifest.Provider, manifest.Message)
	}
	return err
}

func (c *Client) sendDropDecoy() error {
	c.log.Debug("sending drop decoy")
	const loopService = "loop"
	serviceDesc, err := c.GetService(loopService)
	if err != nil {
		return err
	}
	payload := [constants.UserForwardPayloadLength]byte{}
	manifest := &messageManifest{
		Recipient: serviceDesc.Name,
		Provider:  serviceDesc.Provider,
		Message:   payload[:],
		WithSURB:  false,
	}
	return c.send(manifest)
}

func (c *Client) SendUnreliable(recipient, provider string, message []byte) error {
	c.log.Debugf("Send")
	var manifest = messageManifest{
		Recipient: recipient,
		Provider:  provider,
		Message:   message,
		WithSURB:  false,
	}
	_, err := c.egressQueue.EnqueueObject(manifest)
	return err
}

func (c *Client) SendKaetzchenQuery(recipient, provider string, message []byte, wantResponse bool) error {
	c.log.Debugf("Send")

	// Ensure the request message is under the maximum for a single
	// packet, and pad out the message so that it is the correct size.
	if len(message) > constants.UserForwardPayloadLength {
		return fmt.Errorf("invalid message size: %v", len(message))
	}
	payload := make([]byte, constants.UserForwardPayloadLength)
	copy(payload, message)

	var manifest = messageManifest{
		Recipient: recipient,
		Provider:  provider,
		Message:   payload,
		WithSURB:  wantResponse,
	}
	_, err := c.egressQueue.EnqueueObject(manifest)
	return err
}

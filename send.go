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
	"errors"

	coreconstants "github.com/katzenpost/core/constants"
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
	err = c.sendUnreliable(manifest.Recipient, manifest.Provider, manifest.Message)
	return err
}

func (c *Client) sendDropDecoy() error {
	return nil // XXX
}

// SendReliable reliably delivers the message to the recipient's queue
// on the destination provider or returns an error
//func (c *Client) sendReliable(recipient, provider string, message []byte) (*[block.MessageIDLength]byte, error) {
//	c.log.Debugf("sendReliable")
//	return nil, errors.New("failure: sendReliable is not yet implemented")
//}

// SendUnreliable unreliably sends a message to the recipient's queue
// on the destination provider or returns an error
func (c *Client) sendUnreliable(recipient, provider string, message []byte) error {
	c.log.Debugf("sendUnreliable")

	// Ensure the request message is under the maximum for a single
	// packet, and pad out the message so that it is the correct size.
	if len(message) > coreconstants.UserForwardPayloadLength {
		return errors.New("failure: sendUnreliable message payload exceeds maximum.")
	}
	payload := make([]byte, coreconstants.UserForwardPayloadLength)
	copy(payload, message)

	return c.minclient.SendUnreliableCiphertext(recipient, provider, payload)
}

func (c *Client) Send(recipient, provider string, message []byte) error {
	c.log.Debugf("Send")
	var manifest = messageManifest{
		Recipient: recipient,
		Provider:  provider,
		Message:   message,
	}
	_, err := c.egressQueue.EnqueueObject(manifest)
	return err
}

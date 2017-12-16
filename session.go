// session.go - mixnet session client
// Copyright (C) 2017  Yawning Angel, Ruben Pollan, David Stainton
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

// Package client provides the Katzenpost midclient
package client

import (
	"errors"
	"fmt"

	"github.com/katzenpost/core/crypto/ecdh"
	"github.com/katzenpost/core/log"
	"github.com/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/minclient"
	"github.com/katzenpost/minclient/block"
	"github.com/op/go-logging"
)

// MessageIDLength is the length of a message ID
const MessageIDLength = 24

// MessageConsumer is an interface used for
// processing received messages
type MessageConsumer interface {
	ReceivedMessage(message []byte)
	ReceivedACK(messageID *[MessageIDLength]byte, message []byte)
}

// Session holds the client session
type Session struct {
	client          *minclient.Client
	queue           chan string
	log             *logging.Logger
	logBackend      *log.Backend
	messageConsumer MessageConsumer
	connected       chan bool
}

// NewSession stablishes a session with provider using key.
// This method will block until session is connected to the Provider.
func (client *Client) NewSession(user, provider string, linkKeyPriv *ecdh.PrivateKey, consumer MessageConsumer) (*Session, error) {
	var err error
	session := new(Session)
	clientCfg := &minclient.ClientConfig{
		User:       user,
		Provider:   provider,
		LinkKey:    linkKeyPriv,
		LogBackend: client.logBackend,
		PKIClient:  client.cfg.PKIClient,
		OnConnFn:   session.onConnection,
		//OnEmptyFn:   session.onEmpty,
		OnMessageFn: session.onMessage,
		OnACKFn:     session.onACK,
	}
	session.connected = make(chan bool, 0)
	session.messageConsumer = consumer
	session.log = client.logBackend.GetLogger(fmt.Sprintf("%s@%s_session", user, provider))
	session.client, err = minclient.New(clientCfg)
	if err != nil {
		return nil, err
	}
	err = session.waitForConnection()
	if err != nil {
		return nil, err
	}
	return session, nil
}

// Shutdown the session
func (s *Session) Shutdown() {
	s.client.Shutdown()
}

// waitForConnection blocks until the client is
// connected to the Provider
func (s *Session) waitForConnection() error {
	isConnected := <-s.connected
	if !isConnected {
		return errors.New("status is not connected even with status change")
	}
	return nil
}

// Send reliably delivers the message to the recipient's queue
// on the destination provider or returns an error
func (s *Session) Send(recipient, provider string, message []byte) (*[MessageIDLength]byte, error) {
	s.log.Debugf("Send")
	return nil, errors.New("Failure: Send is not yet implemented.")
}

// SendUnreliable unreliably sends a message to the recipient's queue
// on the destination provider or returns an error
func (c *Session) SendUnreliable(recipient, provider string, message []byte) error {
	c.log.Debugf("SendUnreliable")
	fragment := [block.BlockCiphertextLength]byte{}
	if len(message) < block.BlockCiphertextLength {
		copy(fragment[:], message)
	} else {
		return errors.New("Failure: fragmentation not yet implemented.")
	}
	return c.client.SendUnreliableCiphertext(recipient, provider, fragment[:])
}

// OnConnection will be called by the minclient api
// upon connecting to the Provider
func (s *Session) onConnection(isConnected bool) {
	s.log.Debugf("OnConnection")
	s.connected <- isConnected
}

// OnMessage will be called by the minclient api
// upon receiving a message
func (s *Session) onMessage(message []byte) error {
	s.log.Debugf("OnMessage")
	s.messageConsumer.ReceivedMessage(message)
	return nil
}

// OnACK is called by the minclient api whe
// we receive an ACK message
func (s *Session) onACK(surbid *[constants.SURBIDLength]byte, message []byte) error {
	s.log.Debugf("OnACK")
	return nil
}

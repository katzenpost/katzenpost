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
	"github.com/katzenpost/core/crypto/rand"
	"github.com/katzenpost/core/log"
	"github.com/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/minclient"
	"github.com/katzenpost/minclient/block"
	"github.com/op/go-logging"
)

// MessageConsumer is an interface used for
// processing received messages
type MessageConsumer interface {
	ReceivedMessage(senderPubKey *ecdh.PublicKey, message []byte)
	ReceivedACK(messageID *[block.MessageIDLength]byte, message []byte)
}

// Session holds the client session
type Session struct {
	client           *minclient.Client
	queue            chan string
	log              *logging.Logger
	logBackend       *log.Backend
	messageConsumer  MessageConsumer
	connected        chan bool
	userKeyDiscovery UserKeyDiscovery
	identityPrivKey  *ecdh.PrivateKey
}

// NewSession stablishes a session with provider using key.
// This method will block until session is connected to the Provider.
// This method takes the following arguments:
// user: the username of the account
// provider: the Provider name indicates which Provider the user account is on
// identityKeyPriv: the private messaging key for end to end message exchanges with other users
// linkKeyPriv: the private link layer key for our noise wire protocol
// consumer: the message consumer consumes received messages
func (c *Client) NewSession(user, provider string, identityPrivKey *ecdh.PrivateKey, linkPrivKey *ecdh.PrivateKey, consumer MessageConsumer) (*Session, error) {
	var err error
	session := new(Session)
	clientCfg := &minclient.ClientConfig{
		User:        user,
		Provider:    provider,
		LinkKey:     linkPrivKey,
		LogBackend:  c.logBackend,
		PKIClient:   c.cfg.PKIClient,
		OnConnFn:    session.onConnection,
		OnMessageFn: session.onMessage,
		OnACKFn:     session.onACK,
	}
	session.identityPrivKey = identityPrivKey
	session.userKeyDiscovery = c.cfg.UserKeyDiscovery
	session.connected = make(chan bool, 0)
	session.messageConsumer = consumer
	session.log = c.logBackend.GetLogger(fmt.Sprintf("%s@%s_session", user, provider))
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
func (s *Session) Send(recipient, provider string, message []byte) (*[block.MessageIDLength]byte, error) {
	s.log.Debugf("Send")
	return nil, errors.New("failure: Send is not yet implemented")
}

// SendUnreliable unreliably sends a message to the recipient's queue
// on the destination provider or returns an error
func (s *Session) SendUnreliable(recipient, provider string, message []byte) error {
	s.log.Debugf("SendUnreliable")
	messageID := [block.MessageIDLength]byte{}
	_, err := rand.Reader.Read(messageID[:])
	if err != nil {
		return err
	}
	recipientPubKey, err := s.userKeyDiscovery.Get(recipient)
	if err != nil {
		return err
	}
	blocks, err := block.EncryptMessage(&messageID, message, s.identityPrivKey, recipientPubKey)
	if err != nil {
		return err
	}
	for _, block := range blocks {
		err = s.client.SendUnreliableCiphertext(recipient, provider, block)
		if err != nil {
			break
		}
	}
	return err
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
	rBlock, senderPubKey, err := block.DecryptBlock(message, s.identityPrivKey)
	if err != nil {
		return nil
	}
	if rBlock.TotalBlocks == 1 {
		s.messageConsumer.ReceivedMessage(senderPubKey, rBlock.Payload)
	} else {
		return errors.New("failure: message reassembly not yet implemented")
	}
	return nil
}

// OnACK is called by the minclient api whe
// we receive an ACK message
func (s *Session) onACK(surbid *[constants.SURBIDLength]byte, message []byte) error {
	s.log.Debugf("OnACK")
	return nil
}

// session.go - mixnet client session
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

// Package client provides the Katzenpost midclient
package client

import (
	"errors"
	"fmt"

	coreconstants "github.com/katzenpost/core/constants"
	"github.com/katzenpost/core/crypto/ecdh"
	"github.com/katzenpost/core/crypto/rand"
	"github.com/katzenpost/core/log"
	"github.com/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/minclient"
	"github.com/katzenpost/minclient/block"
	"gopkg.in/op/go-logging.v1"
)

// SessionConfig is specifies the configuration for a new session
type SessionConfig struct {
	User        string
	Provider    string
	LinkPrivKey *ecdh.PrivateKey
}

// Session holds the client session
type Session struct {
	cfg             *SessionConfig
	minclient       *minclient.Client
	log             *logging.Logger
	logBackend      *log.Backend
	connected       chan bool
	identityPrivKey *ecdh.PrivateKey
}

// NewSession stablishes a session with provider using key.
// This method will block until session is connected to the Provider.
// This method takes the following arguments:
// user: the username of the account
// provider: the Provider name indicates which Provider the user account is on
// identityKeyPriv: the private messaging key for end to end message exchanges with other users
// linkKeyPriv: the private link layer key for our noise wire protocol
// consumer: the message consumer consumes received messages
func (c *Client) NewSession(cfg *SessionConfig) (*Session, error) {
	var err error
	session := new(Session)
	clientCfg := &minclient.ClientConfig{
		User:        cfg.User,
		Provider:    cfg.Provider,
		LinkKey:     cfg.LinkPrivKey,
		LogBackend:  c.cfg.LogBackend,
		PKIClient:   c.cfg.PKIClient,
		OnConnFn:    session.onConnection,
		OnMessageFn: session.onMessage,
		OnACKFn:     session.onACK,
	}
	session.cfg = cfg
	session.connected = make(chan bool, 0)
	session.log = c.cfg.LogBackend.GetLogger(fmt.Sprintf("%s@%s_session", cfg.User, cfg.Provider))
	session.minclient, err = minclient.New(clientCfg)
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
	s.minclient.Shutdown()
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
	if len(message) > coreconstants.UserForwardPayloadLength {
		return errors.New("failure: SendUnreliable message payload exceeds maximum.")
	}
	return s.minclient.SendUnreliableCiphertext(recipient, provider, message)
}

// OnConnection will be called by the minclient api
// upon connecting to the Provider
func (s *Session) onConnection(err error) {
	s.log.Debugf("OnConnection")
	if err == nil {
		s.connected <- true
	}
}

// OnMessage will be called by the minclient api
// upon receiving a message
func (s *Session) onMessage(ciphertextBlock []byte) error {
	s.log.Debugf("OnMessage")
	return nil
}

// OnACK is called by the minclient api whe
// we receive an ACK message
func (s *Session) onACK(surbid *[constants.SURBIDLength]byte, message []byte) error {
	s.log.Debugf("OnACK")
	return nil
}

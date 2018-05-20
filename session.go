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
	"context"
	"errors"
	"fmt"
	mrand "math/rand"
	"path/filepath"
	"time"

	"github.com/katzenpost/client/internal/pkiclient"
	coreconstants "github.com/katzenpost/core/constants"
	"github.com/katzenpost/core/crypto/ecdh"
	"github.com/katzenpost/core/crypto/rand"
	"github.com/katzenpost/core/epochtime"
	"github.com/katzenpost/core/pki"
	"github.com/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/minclient"
	"github.com/katzenpost/minclient/block"
)

// NewSession stablishes a session with provider using key.
// This method will block until session is connected to the Provider.
func (c *Client) NewSession() error {
	var err error

	// create a pkiclient for our own client lookups
	proxyCfg := c.cfg.UpstreamProxyConfig()
	c.pkiClient, err = c.cfg.NonvotingAuthority.New(c.logBackend, proxyCfg)
	if err != nil {
		return err
	}

	// create a pkiclient for minclient's use
	pkiClient, err := c.cfg.NonvotingAuthority.New(c.logBackend, proxyCfg)
	if err != nil {
		return err
	}
	pkiCacheClient := pkiclient.New(pkiClient)

	id := fmt.Sprintf("%s@%s", c.cfg.Account.User, c.cfg.Account.Provider)
	basePath := filepath.Join(c.cfg.Proxy.DataDir, id)
	linkPriv := filepath.Join(basePath, "link.private.pem")
	linkPub := filepath.Join(basePath, "link.public.pem")
	if c.linkKey, err = ecdh.Load(linkPriv, linkPub, rand.Reader); err != nil {
		return err
	}

	// Configure and bring up the minclient instance.
	clientCfg := &minclient.ClientConfig{
		User:                c.cfg.Account.User,
		Provider:            c.cfg.Account.Provider,
		ProviderKeyPin:      c.cfg.Account.ProviderKeyPin,
		LinkKey:             c.linkKey,
		LogBackend:          c.logBackend,
		PKIClient:           pkiCacheClient,
		OnConnFn:            c.onConnection,
		OnMessageFn:         c.onMessage,
		OnACKFn:             c.onACK,
		OnDocumentFn:        c.onDocument,
		DialContextFn:       proxyCfg.ToDialContext("nonvoting:" + c.cfg.NonvotingAuthority.PublicKey.String()),
		MessagePollInterval: time.Duration(c.cfg.Debug.PollingInterval) * time.Second, // XXX
		EnableTimeSync:      false,                                                    // Be explicit about it.
	}

	//c.authority = authority.NewStore(c.logBackend, proxyCfg)
	c.connected = make(chan bool, 0)
	c.log = c.logBackend.GetLogger(fmt.Sprintf("%s@%s_c", c.cfg.Account.User, c.cfg.Account.Provider))
	c.minclient, err = minclient.New(clientCfg)
	if err != nil {
		return err
	}
	err = c.waitForConnection()
	return err
}

// waitForConnection blocks until the client is
// connected to the Provider
func (c *Client) waitForConnection() error {
	isConnected := <-c.connected
	if !isConnected {
		return errors.New("status is not connected even with status change")
	}
	return nil
}

// Send reliably delivers the message to the recipient's queue
// on the destination provider or returns an error
func (c *Client) Send(recipient, provider string, message []byte) (*[block.MessageIDLength]byte, error) {
	c.log.Debugf("Send")
	return nil, errors.New("failure: Send is not yet implemented")
}

// SendUnreliable unreliably sends a message to the recipient's queue
// on the destination provider or returns an error
func (c *Client) SendUnreliable(recipient, provider string, message []byte) error {
	c.log.Debugf("SendUnreliable")

	// Ensure the request message is under the maximum for a single
	// packet, and pad out the message so that it is the correct size.
	if len(message) > coreconstants.UserForwardPayloadLength {
		return errors.New("failure: SendUnreliable message payload exceeds maximum.")
	}
	payload := make([]byte, coreconstants.UserForwardPayloadLength)
	copy(payload, message)

	return c.minclient.SendUnreliableCiphertext(recipient, provider, payload)
}

// GetService returns a randomly selected service
// matching the specified service name
func (c *Client) GetService(serviceName string) (*ServiceDescriptor, error) {
	epoch, _, _ := epochtime.Now()
	ctx, _ := context.WithTimeout(context.Background(), 10*time.Second) // XXX
	doc, _, err := c.pkiClient.Get(ctx, epoch)
	if err != nil {
		return nil, err
	}
	serviceDescriptors := FindServices(serviceName, doc)
	return &serviceDescriptors[mrand.Intn(len(serviceDescriptors))], nil
}

// OnConnection will be called by the minclient api
// upon connecting to the Provider
func (c *Client) onConnection(err error) {
	c.log.Debugf("OnConnection")
	if err == nil {
		c.connected <- true
	}
}

// OnMessage will be called by the minclient api
// upon receiving a message
func (c *Client) onMessage(ciphertextBlock []byte) error {
	c.log.Debugf("OnMessage")
	return nil
}

// OnACK is called by the minclient api whe
// we receive an ACK message
func (c *Client) onACK(surbid *[constants.SURBIDLength]byte, message []byte) error {
	c.log.Debugf("OnACK")
	return nil
}

func (c *Client) onDocument(doc *pki.Document) {
	c.log.Debugf("onDocument(): Epoch %v", doc.Epoch)
}

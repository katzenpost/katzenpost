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
	mrand "math/rand"
	"time"

	"github.com/katzenpost/client/internal/pkiclient"
	"github.com/katzenpost/core/pki"
	"github.com/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/minclient"
)

type messageManifest struct {
	Recipient string
	Provider  string
	Message   []byte
	WithSURB  bool
}

// NewSession establishes a session with provider using key.
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
		MessagePollInterval: time.Duration(c.cfg.Debug.PollingInterval) * time.Second,
		EnableTimeSync:      false, // Be explicit about it.
	}

	c.log = c.logBackend.GetLogger(fmt.Sprintf("%s@%s_c", c.cfg.Account.User, c.cfg.Account.Provider))
	c.minclient, err = minclient.New(clientCfg)
	if err != nil {
		return err
	}

	c.Go(c.worker)
	return nil
}

// GetService returns a randomly selected service
// matching the specified service name
func (c *Client) GetService(serviceName string) (*ServiceDescriptor, error) {
	for !c.hasPKIDoc {
		return nil, errors.New("GetService failure, missing PKI document.")
	}
	doc := c.minclient.CurrentDocument()
	if doc == nil {
		return nil, errors.New("pki doc is nil")
	}
	serviceDescriptors := FindServices(serviceName, doc)
	return &serviceDescriptors[mrand.Intn(len(serviceDescriptors))], nil
}

func (c *Client) WaitForPKIDocument() {
	c.condGotPKIDoc.Wait()
}

func (c *Client) WaitForMessage() {
	c.condGotMessage.Wait()
}

func (c *Client) WaitForReply() {
	c.condGotReply.Wait()
}

func (c *Client) WaitForConnect() {
	c.condGotConnect.Wait()
}

// OnConnection will be called by the minclient api
// upon connecting to the Provider
func (c *Client) onConnection(err error) {
	c.log.Debugf("OnConnection")
	if err == nil {
		c.opCh <- opConnStatusChanged{
			isConnected: true,
		}
		c.condGotConnect.Broadcast()
	}
}

// OnMessage will be called by the minclient api
// upon receiving a message
func (c *Client) onMessage(ciphertextBlock []byte) error {
	c.log.Debugf("OnMessage")
	c.condGotMessage.Broadcast()
	return nil
}

// OnACK is called by the minclient api whe
// we receive an ACK message
func (c *Client) onACK(surbid *[constants.SURBIDLength]byte, message []byte) error {
	c.log.Debugf("OnACK")
	c.condGotReply.Broadcast()
	return nil
}

func (c *Client) onDocument(doc *pki.Document) {
	c.log.Debugf("onDocument(): Epoch %v", doc.Epoch)
	c.condGotPKIDoc.Broadcast()
	c.hasPKIDoc = true
	c.opCh <- opNewDocument{
		doc: doc,
	}
}

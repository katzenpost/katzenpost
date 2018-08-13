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

package client

import (
	"encoding/hex"
	"errors"
	"fmt"
	mrand "math/rand"
	"time"

	"github.com/katzenpost/client/internal/pkiclient"
	cconstants "github.com/katzenpost/core/constants"
	"github.com/katzenpost/core/pki"
	"github.com/katzenpost/core/sphinx"
	"github.com/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/minclient"
)

const (
	surbTypeACK       = 0
	surbTypeKaetzchen = 1
	surbTypeInternal  = 2
)

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
	doc := c.minclient.CurrentDocument()
	if doc == nil {
		return nil, errors.New("pki doc is nil")
	}
	serviceDescriptors := FindServices(serviceName, doc)
	if len(serviceDescriptors) == 0 {
		return nil, errors.New("GetService failure, service not found in pki doc.")
	}
	return &serviceDescriptors[mrand.Intn(len(serviceDescriptors))], nil
}

func (c *Client) WaitForPKIDocument() {
	c.condGotPKIDoc.L.Lock()
	defer c.condGotPKIDoc.L.Unlock()
	c.condGotPKIDoc.Wait()
}

// OnConnection will be called by the minclient api
// upon connecting to the Provider
func (c *Client) onConnection(err error) {
	if err == nil {
		c.condGotConnect.L.Lock()
		c.opCh <- opConnStatusChanged{
			isConnected: true,
		}
		c.condGotConnect.Broadcast()
		c.condGotConnect.L.Unlock()
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
func (c *Client) onACK(surbID *[constants.SURBIDLength]byte, ciphertext []byte) error {
	idStr := fmt.Sprintf("[%v]", hex.EncodeToString(surbID[:]))
	c.log.Infof("OnACK with SURBID %x", idStr)

	msgRef, ok := c.surbIDMap[*surbID]
	if !ok {
		c.log.Debug("wtf, received reply with unexpected SURBID")
		return nil
	}
	_, ok = c.replyNotifyMap[*msgRef.ID]
	if !ok {
		c.log.Infof("wtf, received reply with no reply notification mutex, map len is %d", len(c.replyNotifyMap))
		for key, _ := range c.replyNotifyMap {
			c.log.Infof("key %x", key)
		}
		return nil
	}

	plaintext, err := sphinx.DecryptSURBPayload(ciphertext, msgRef.Key)
	if err != nil {
		c.log.Infof("SURB Reply decryption failure: %s", err)
		return err
	}
	if len(plaintext) != cconstants.ForwardPayloadLength {
		c.log.Warningf("Discarding SURB %v: Invalid payload size: %v", idStr, len(plaintext))
		return nil
	}

	switch msgRef.SURBType {
	case surbTypeACK:
		// XXX TODO fix me
	case surbTypeKaetzchen, surbTypeInternal:
		msgRef.Reply = plaintext[2:]
		c.replyNotifyMap[*msgRef.ID].Unlock()
	default:
		c.log.Warningf("Discarding SURB %v: Unknown type: 0x%02x", idStr, msgRef.SURBType)
	}
	return nil
}

func (c *Client) onDocument(doc *pki.Document) {
	c.log.Debugf("onDocument(): Epoch %v", doc.Epoch)
	c.hasPKIDoc = true
	c.condGotPKIDoc.L.Lock()
	c.opCh <- opNewDocument{
		doc: doc,
	}
	c.condGotPKIDoc.Broadcast()
	c.condGotPKIDoc.L.Unlock()
}

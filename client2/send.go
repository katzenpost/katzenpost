// SPDX-FileCopyrightText: Copyright (C) 2017  Yawning Angel.
// SPDX-License-Identifier: AGPL-3.0-only

package client2

import (
	"errors"
	"fmt"
	"time"

	cpki "github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/sphinx/path"
)

// SendSphinxPacket sends the given Sphinx packet.
func (c *Client) SendSphinxPacket(pkt []byte) error {
	return c.conn.sendPacket(pkt)
}

func (c *Client) ComposeSphinxPacket(request *Request) ([]byte, []byte, time.Duration, error) {
	doc := c.CurrentDocument()
	if doc == nil {
		return nil, nil, 0, errors.New("client2: no PKI document for current epoch")
	}
	src, err := doc.GetProviderByKeyHash(c.conn.provider)
	if err != nil {
		return nil, nil, 0, err
	}
	source := src.IdentityKey.Sum256()
	return c.packetFactory.ComposePacket(
		doc,
		request.RecipientQueueID,
		&source,
		request.RecipientQueueID,
		request.DestinationIdHash,
		request.SURBID,
		request.Payload,
	)
}

// SendCiphertext sends the ciphertext b to the recipient/provider, with a
// SURB identified by surbID, and returns the SURB decryption key and total
// round trip delay.
func (c *Client) SendCiphertext(request *Request) ([]byte, time.Duration, error) {
	pkt, k, rtt, err := c.ComposeSphinxPacket(request)
	if err != nil {
		panic(fmt.Sprintf("COMPOSE SPHINX PACKET FAIL %s", err.Error()))
	}
	err = c.conn.sendPacket(pkt)
	return k, rtt, err
}

func (c *Client) logPath(doc *cpki.Document, p []*path.PathHop) error {
	s, err := path.ToString(doc, p)
	if err != nil {
		return err
	}

	for _, v := range s {
		c.log.Debug(v)
	}
	return nil
}

// send.go - Send related routines.
// Copyright (C) 2017  Yawning Angel.
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

package client2

import (
	"fmt"
	"time"

	"github.com/katzenpost/katzenpost/core/crypto/rand"
	"github.com/katzenpost/katzenpost/core/epochtime"
	cpki "github.com/katzenpost/katzenpost/core/pki"
	sConstants "github.com/katzenpost/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/katzenpost/core/sphinx/path"
)

// SendSphinxPacket sends the given Sphinx packet.
func (c *Client) SendSphinxPacket(pkt []byte) error {
	return c.conn.sendPacket(pkt)
}

// ComposeSphinxPacket is used to compose Sphinx packets.
func (c *Client) ComposeSphinxPacket(recipient []byte, provider *[32]byte, surbID *[sConstants.SURBIDLength]byte, message []byte) ([]byte, []byte, time.Duration, error) {
	c.log.Info("ComposeSphinxPacket START")
	if len(recipient) > sConstants.RecipientIDLength {
		return nil, nil, 0, fmt.Errorf("client2: invalid recipient: '%v'", recipient)
	}

	if len(message) > c.geo.UserForwardPayloadLength {
		return nil, nil, 0, fmt.Errorf("message too large: %v > %v", len(message), c.geo.UserForwardPayloadLength)
	}

	payload := make([]byte, c.geo.UserForwardPayloadLength)
	copy(payload, message)

	for {
		unixTime := c.pki.skewedUnixTime()
		_, _, budget := epochtime.FromUnix(unixTime)
		start := time.Now()

		// Select the forward path.
		now := time.Unix(unixTime, 0)

		if c.conn.provider == nil {
			panic("source provider cannot be nil")
		}

		fwdPath, then, err := c.makePath(recipient, provider, surbID, now, true)
		if err != nil {
			return nil, nil, 0, err
		}

		revPath := make([]*path.PathHop, 0)
		if surbID != nil {
			if c.conn.queueID == nil {
				panic("sender queueID cannot be nil")
			}
			revPath, then, err = c.makePath(c.conn.queueID, provider, surbID, then, false)
			if err != nil {
				return nil, nil, 0, err
			}
		}

		// If the path selection process ends up straddling an epoch
		// transition, then redo the path selection.
		if time.Since(start) > budget {
			continue
		}

		// It is possible, but unlikely that a series of delays exceeding
		// the PKI publication imposted limitations will be selected.  When
		// that happens, the path selection must be redone.
		if then.Sub(now) < epochtime.Period*2 {
			if surbID != nil {
				payload := make([]byte, 2, 2+c.geo.SURBLength+len(message))
				payload[0] = 1 // Packet has a SURB.
				surb, k, err := c.sphinx.NewSURB(rand.Reader, revPath)
				if err != nil {
					return nil, nil, 0, err
				}
				payload = append(payload, surb...)
				payload = append(payload, message...)

				pkt, err := c.sphinx.NewPacket(rand.Reader, fwdPath, payload)
				if err != nil {
					return nil, nil, 0, err
				}
				return pkt, k, then.Sub(now), err
			} else {
				pkt, err := c.sphinx.NewPacket(rand.Reader, fwdPath, payload)
				if err != nil {
					return nil, nil, 0, err
				}
				return pkt, nil, then.Sub(now), nil
			}
		}
	}
}

// SendCiphertext sends the ciphertext b to the recipient/provider, with a
// SURB identified by surbID, and returns the SURB decryption key and total
// round trip delay.
func (c *Client) SendCiphertext(recipient []byte, provider *[32]byte, surbID *[sConstants.SURBIDLength]byte, b []byte) ([]byte, time.Duration, error) {
	c.log.Info("SendCiphertext")
	c.log.Info("BEFORE COMPOSE SPHINX PACKET")
	pkt, k, rtt, err := c.ComposeSphinxPacket(recipient, provider, surbID, b)
	c.log.Info("AFTER COMPOSE SPHINX PACKET")
	if err != nil {
		c.log.Infof("COMPOSE SPHINX PACKET FAIL %s", err.Error())
		return nil, 0, err
	}
	c.log.Info("BEFORE sendPacket")
	err = c.conn.sendPacket(pkt)
	return k, rtt, err
}

func (c *Client) makePath(recipient []byte, provider *[32]byte, surbID *[sConstants.SURBIDLength]byte, baseTime time.Time, isForward bool) ([]*path.PathHop, time.Time, error) {
	if c.conn.provider == nil {
		panic("source provider cannot be nil")
	}
	srcProvider, dstProvider := c.conn.provider, provider
	if !isForward {
		srcProvider, dstProvider = dstProvider, srcProvider
	}

	// Get the current PKI document.
	doc := c.CurrentDocument()
	if doc == nil {
		return nil, time.Time{}, newPKIError("client2: no PKI document for current epoch")
	}

	// Get the descriptors.
	src, err := doc.GetProviderByKeyHash(srcProvider)
	if err != nil {
		return nil, time.Time{}, newPKIError("client2: failed to find source Provider: %v", err)
	}
	dst, err := doc.GetProviderByKeyHash(dstProvider)
	if err != nil {
		return nil, time.Time{}, newPKIError("client2: failed to find destination Provider: %v", err)
	}

	rng := rand.NewMath()
	p, t, err := path.New(rng, c.cfg.SphinxGeometry, doc, recipient, src, dst, surbID, baseTime, true, isForward)
	if err == nil {
		c.logPath(doc, p)
	}

	return p, t, err
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

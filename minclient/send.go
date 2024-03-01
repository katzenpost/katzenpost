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

package minclient

import (
	"fmt"
	"time"

	"github.com/katzenpost/hpqc/rand"
	"github.com/katzenpost/katzenpost/core/epochtime"
	cpki "github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/sphinx"
	sConstants "github.com/katzenpost/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/katzenpost/core/sphinx/path"
)

// SendSphinxPacket sends the given Sphinx packet.
func (c *Client) SendSphinxPacket(pkt []byte) error {
	return c.conn.sendPacket(pkt)
}

// ComposeSphinxPacket is used to compose Sphinx packets.
func (c *Client) ComposeSphinxPacket(recipient, gateway string, surbID *[sConstants.SURBIDLength]byte, b []byte) ([]byte, []byte, time.Duration, error) {
	if len(recipient) > sConstants.RecipientIDLength {
		return nil, nil, 0, fmt.Errorf("minclient: invalid recipient: '%v'", recipient)
	}
	if len(b) != c.geo.UserForwardPayloadLength {
		return nil, nil, 0, fmt.Errorf("minclient: invalid ciphertext size: %v", len(b))
	}

	// Wrap the ciphertext in a BlockSphinxCiphertext.
	payload := make([]byte, 2+c.geo.SURBLength, 2+c.geo.SURBLength+len(b))
	payload = append(payload, b...)

	for {
		unixTime := c.pki.skewedUnixTime()
		_, _, budget := epochtime.FromUnix(unixTime)
		start := time.Now()

		// Select the forward path.
		now := time.Unix(unixTime, 0)

		fwdPath, then, err := c.makePath(recipient, gateway, surbID, now, true)
		if err != nil {
			return nil, nil, 0, err
		}

		revPath := make([]*sphinx.PathHop, 0)
		if surbID != nil {
			revPath, then, err = c.makePath(c.cfg.User, gateway, surbID, then, false)
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
				payload := make([]byte, 2, 2+c.geo.SURBLength+len(b))
				payload[0] = 1 // Packet has a SURB.
				surb, k, err := c.sphinx.NewSURB(rand.Reader, revPath)
				if err != nil {
					return nil, nil, 0, err
				}
				payload = append(payload, surb...)
				payload = append(payload, b...)

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

// SendUnreliableCiphertext sends the ciphertext b to the recipient/provider,
// in an unreliable manner.  No notification of the packet being received will
// be generated by the recipient's provider.
func (c *Client) SendUnreliableCiphertext(recipient, provider string, b []byte) error {
	pkt, _, _, err := c.ComposeSphinxPacket(recipient, provider, nil, b)
	if err != nil {
		return err
	}
	return c.SendSphinxPacket(pkt)
}

// SendCiphertext sends the ciphertext b to the recipient/provider, with a
// SURB identified by surbID, and returns the SURB decryption key and total
// round trip delay.
func (c *Client) SendCiphertext(recipient, provider string, surbID *[sConstants.SURBIDLength]byte, b []byte) ([]byte, time.Duration, error) {
	pkt, k, rtt, err := c.ComposeSphinxPacket(recipient, provider, surbID, b)
	if err != nil {
		return nil, 0, err
	}
	err = c.conn.sendPacket(pkt)
	return k, rtt, err
}

func (c *Client) makePath(recipient, destNode string, surbID *[sConstants.SURBIDLength]byte, baseTime time.Time, isForward bool) ([]*sphinx.PathHop, time.Time, error) {
	srcNode, dstNode := c.cfg.Gateway, destNode
	if !isForward {
		srcNode, dstNode = dstNode, srcNode
	}

	// Get the current PKI document.
	doc := c.CurrentDocument()
	if doc == nil {
		return nil, time.Time{}, newPKIError("minclient: no PKI document for current epoch")
	}

	// Get the descriptors.
	src, err := doc.GetGateway(srcNode)
	if err != nil {
		return nil, time.Time{}, newPKIError("minclient: failed to find source Provider: %v", err)
	}
	dst, err := doc.GetServiceNode(dstNode)
	if err != nil {
		return nil, time.Time{}, newPKIError("minclient: failed to find destination Provider: %v", err)
	}

	p, t, err := path.New(c.rng, c.cfg.SphinxGeometry, doc, []byte(recipient), src, dst, surbID, baseTime, true, isForward)
	if err == nil {
		c.logPath(doc, p)
	}

	return p, t, err
}

func (c *Client) logPath(doc *cpki.Document, p []*sphinx.PathHop) error {
	s, err := path.ToString(doc, p)
	if err != nil {
		return err
	}

	for _, v := range s {
		c.log.Debug(v)
	}
	return nil
}

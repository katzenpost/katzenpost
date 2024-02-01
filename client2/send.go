// SPDX-FileCopyrightText: Copyright (C) 2017  Yawning Angel.
// SPDX-License-Identifier: AGPL-3.0-only

package client2

import (
	"errors"
	"fmt"
	"time"

	"github.com/katzenpost/katzenpost/core/crypto/rand"
	"github.com/katzenpost/katzenpost/core/epochtime"
	cpki "github.com/katzenpost/katzenpost/core/pki"
	sConstants "github.com/katzenpost/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/katzenpost/core/sphinx/path"
)

// ComposeSphinxPacket is used to compose Sphinx packets.
func (c *Client) ComposeSphinxPacket(request *Request) (pkt []byte, surbkey []byte, rtt time.Duration, err error) {
	if request.DestinationIdHash == nil {
		return nil, nil, 0, errors.New("request.DestinationIdHash is nil")
	}
	if len(request.RecipientQueueID) > sConstants.RecipientIDLength {
		return nil, nil, 0, fmt.Errorf("client2: invalid recipient: '%v'", request.RecipientQueueID)
	}

	if len(request.Payload) > c.geo.UserForwardPayloadLength {
		return nil, nil, 0, fmt.Errorf("message too large: %v > %v", len(request.Payload), c.geo.UserForwardPayloadLength)
	}

	payload := make([]byte, c.geo.UserForwardPayloadLength)
	copy(payload, request.Payload)

	for {
		unixTime := c.pki.skewedUnixTime()
		_, _, budget := epochtime.FromUnix(unixTime)
		start := time.Now()

		// Select the forward path.
		now := time.Unix(unixTime, 0)

		if c.conn.provider == nil {
			panic("source provider cannot be nil")
		}

		fwdPath, then, err := c.makePath(request.RecipientQueueID, request.DestinationIdHash, request.SURBID, now, true)
		if err != nil {
			return nil, nil, 0, err
		}

		revPath := make([]*path.PathHop, 0)
		if request.SURBID != nil {
			if c.conn.queueID == nil {
				panic("sender queueID cannot be nil")
			}
			revPath, then, err = c.makePath(c.conn.queueID, request.DestinationIdHash, request.SURBID, then, false)
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
			if request.WithSURB {
				payload := make([]byte, 2, 2+c.geo.SURBLength+len(request.Payload))
				payload[0] = 1 // Packet has a SURB.
				surb, k, err := c.sphinx.NewSURB(rand.Reader, revPath)
				if err != nil {
					return nil, nil, 0, err
				}
				payload = append(payload, surb...)
				payload = append(payload, request.Payload...)

				blob := make([]byte, c.geo.ForwardPayloadLength)
				copy(blob, payload)

				pkt, err := c.sphinx.NewPacket(rand.Reader, fwdPath, blob)
				if err != nil {
					return nil, nil, 0, err
				}
				return pkt, k, then.Sub(now), err
			} else {
				blob := make([]byte, c.geo.ForwardPayloadLength)
				copy(blob, payload)

				pkt, err := c.sphinx.NewPacket(rand.Reader, fwdPath, blob)
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
// round trip delay. Blocks until packet is sent on the wire.
func (c *Client) SendCiphertext(request *Request) ([]byte, time.Duration, error) {
	if request.DestinationIdHash == nil {
		return nil, 0, errors.New("request.DestinationIdHash is nil")
	}

	pkt, k, rtt, err := c.ComposeSphinxPacket(request)
	if err != nil {
		panic(fmt.Sprintf("COMPOSE SPHINX PACKET FAIL %s", err.Error()))
	}
	err = c.conn.sendPacket(pkt)
	return k, rtt, err
}

func (c *Client) SendPacket(pkt []byte) error {
	err := c.conn.sendPacket(pkt)
	if err != nil {
		c.log.Warnf("failed to send packet %s", err)
	}
	return err
}

func (c *Client) makePath(recipient []byte, provider *[32]byte, surbID *[sConstants.SURBIDLength]byte, baseTime time.Time, isForward bool) ([]*path.PathHop, time.Time, error) {
	if c.conn.provider == nil {
		panic("source provider cannot be nil")
	}
	if c.conn.provider == nil {
		panic("c.conn.provider is nil")
	}
	if provider == nil {
		panic("provider is nil")
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
		// XXX Do not log the paths, too verbose.
		// c.logPath(doc, p)
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

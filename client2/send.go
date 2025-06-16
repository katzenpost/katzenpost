// SPDX-FileCopyrightText: Copyright (C) 2017  Yawning Angel.
// SPDX-License-Identifier: AGPL-3.0-only

package client2

import (
	"errors"
	"fmt"
	"time"

	"github.com/katzenpost/hpqc/rand"

	"github.com/katzenpost/katzenpost/core/epochtime"
	cpki "github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/sphinx"
	sConstants "github.com/katzenpost/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/katzenpost/core/sphinx/path"
)

// ComposeSphinxPacket is used to compose Sphinx packets.
func (c *Client) ComposeSphinxPacket(request *Request) (pkt []byte, surbkey []byte, rtt time.Duration, err error) {
	if request.DestinationIdHash == nil {
		return nil, nil, 0, errors.New("request.DestinationIdHash is nil")
	}
	if len(request.RecipientQueueID) == 0 {
		return nil, nil, 0, errors.New("client2: recipient is nil")
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
		// Check if we're shutting down to avoid races
		select {
		case <-c.HaltCh():
			return nil, nil, 0, ErrShutdown
		default:
		}

		unixTime := c.pki.skewedUnixTime()
		_, _, budget := epochtime.FromUnix(unixTime)
		start := time.Now()

		// Select the forward path.
		now := time.Unix(unixTime, 0)

		gateway := c.conn.getGateway()
		if gateway == nil {
			panic("source gateway cannot be nil")
		}

		fwdPath, then, err := c.makePath(request.RecipientQueueID, request.DestinationIdHash, request.SURBID, now, true, gateway)
		if err != nil {
			return nil, nil, 0, err
		}

		revPath := make([]*sphinx.PathHop, 0)
		if request.SURBID != nil {
			if c.conn.queueID == nil {
				panic("sender queueID cannot be nil")
			}
			revPath, then, err = c.makePath(c.conn.queueID, request.DestinationIdHash, request.SURBID, then, false, gateway)
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
		// Don't panic on shutdown or other errors, return them gracefully
		return nil, 0, err
	}
	err = c.conn.sendPacket(pkt)
	return k, rtt, err
}

func (c *Client) SendPacket(pkt []byte) error {
	err := c.conn.sendPacket(pkt)
	if err != nil {
		c.log.Warningf("failed to send packet %s", err)
	}
	return err
}

func (c *Client) makePath(recipient []byte, destination *[32]byte, surbID *[sConstants.SURBIDLength]byte, baseTime time.Time, isForward bool, gateway *[32]byte) ([]*sphinx.PathHop, time.Time, error) {
	if gateway == nil {
		panic("gateway is nil")
	}
	if destination == nil {
		panic("destination is nil")
	}

	// Get the current PKI document.
	_, doc := c.CurrentDocument()
	if doc == nil {
		return nil, time.Time{}, newPKIError("client2: no PKI document for current epoch")
	}

	src, dst, err := c.getSourceAndDestinationNodes(doc, gateway, destination, isForward)
	if err != nil {
		return nil, time.Time{}, err
	}

	rng := rand.NewMath()
	p, t, err := path.New(rng, c.cfg.SphinxGeometry, doc, recipient, src, dst, surbID, baseTime, true, isForward)
	if err == nil {
		// XXX Do not log the paths, too verbose.
		// c.logPath(doc, p)
	}

	if len(p) == 0 {
		panic("path is zero length")
	}

	return p, t, err
}

// getSourceAndDestinationNodes retrieves the source and destination mix descriptors based on direction
func (c *Client) getSourceAndDestinationNodes(doc *cpki.Document, gateway, destination *[32]byte, isForward bool) (*cpki.MixDescriptor, *cpki.MixDescriptor, error) {
	srcNode, dstNode := gateway, destination
	if !isForward {
		srcNode, dstNode = dstNode, srcNode
	}

	var src, dst *cpki.MixDescriptor
	var err error

	if isForward {
		src, err = doc.GetGatewayByKeyHash(srcNode)
		if err != nil {
			return nil, nil, newPKIError("client2: failed to find source Gateway: %v", err)
		}
		dst, err = doc.GetServiceNodeByKeyHash(dstNode)
		if err != nil {
			return nil, nil, newPKIError("client2: failed to find destination service node: %v", err)
		}
	} else {
		src, err = doc.GetServiceNodeByKeyHash(srcNode)
		if err != nil {
			return nil, nil, newPKIError("client2: failed to find source service node: %v", err)
		}
		dst, err = doc.GetGatewayByKeyHash(dstNode)
		if err != nil {
			return nil, nil, newPKIError("client2: failed to find destination gateway node: %v", err)
		}
	}

	return src, dst, nil
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

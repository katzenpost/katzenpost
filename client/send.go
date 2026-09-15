// SPDX-FileCopyrightText: Copyright (C) 2017  Yawning Angel.
// SPDX-License-Identifier: AGPL-3.0-only

package client

import (
	"errors"
	"fmt"
	"time"

	"github.com/katzenpost/hpqc/rand"

	"github.com/katzenpost/katzenpost/client/thin"
	"github.com/katzenpost/katzenpost/core/epochtime"
	cpki "github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/sphinx"
	sConstants "github.com/katzenpost/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/katzenpost/core/sphinx/path"
)

// maxPathSelectionAttempts bounds how many times ComposeSphinxPacket and
// ComposeSphinxPacketForQuery will re-roll path selection when selection
// straddles an epoch boundary or returns a path whose total delay exceeds
// 2 × epochtime.Period. Without this cap a pathological PKI document
// could spin either loop at full CPU per outbound packet until shutdown.
// 32 is well clear of the handful of retries a healthy epoch rollover
// typically needs, while remaining a small, diagnosable ceiling.
const maxPathSelectionAttempts = 32

// validateSendMessageRequest validates the fields needed to compose a Sphinx packet.
func validateSendMessageRequest(destinationIdHash *[32]byte, recipientQueueID []byte, payload []byte, maxPayloadLen int) error {
	if destinationIdHash == nil {
		return errors.New("request.DestinationIdHash is nil")
	}
	if len(recipientQueueID) == 0 {
		return errors.New("client: recipient is nil")
	}
	if len(recipientQueueID) > sConstants.RecipientIDLength {
		return fmt.Errorf("client: invalid recipient: '%v'", recipientQueueID)
	}
	if len(payload) > maxPayloadLen {
		return fmt.Errorf("message too large: %v > %v", len(payload), maxPayloadLen)
	}
	return nil
}

// Route names the hops a composed Sphinx packet travels, in path order.
// Forward runs from the gateway to the destination; Return is the path the
// SURB takes back, and is empty when the packet carries no SURB.
//
// The names come from the consensus the path was selected against, so a
// Route is meaningful only alongside that document's epoch. A nil Route
// means the hops could not be named, which is not the same as a packet
// with no hops.
type Route struct {
	// Forward names the hops from the gateway to the destination.
	Forward []string

	// Return names the hops the SURB travels back over, if there is one.
	Return []string
}

// Forward hops of r, tolerating a nil receiver so that a send whose hops
// could not be named still yields a well-formed, empty answer.
func (r *Route) forward() []string {
	if r == nil {
		return nil
	}
	return r.Forward
}

// Return hops of r, with the same nil tolerance as forward.
func (r *Route) back() []string {
	if r == nil {
		return nil
	}
	return r.Return
}

// routeNames resolves the two halves of a selected path to node names against
// the current consensus.
//
// Naming is best effort by design: the packet is already correctly addressed
// by key hash, and these names exist only so a caller can attribute a lost
// reply. A document that cannot name a hop therefore yields nil rather than
// failing a send that would otherwise have succeeded.
func (c *Client) routeNames(fwdPath, revPath []*sphinx.PathHop) *Route {
	_, doc := c.CurrentDocument()
	if doc == nil {
		return nil
	}
	fwd, err := hopNames(doc, fwdPath)
	if err != nil {
		c.log.Debugf("routeNames: cannot name forward hops: %v", err)
		return nil
	}
	route := &Route{Forward: fwd}
	if len(revPath) == 0 {
		return route
	}
	rev, err := hopNames(doc, revPath)
	if err != nil {
		c.log.Debugf("routeNames: cannot name return hops: %v", err)
		return route
	}
	route.Return = rev
	return route
}

// hopNames maps each hop to the node name the consensus gives it.
func hopNames(doc *cpki.Document, p []*sphinx.PathHop) ([]string, error) {
	names := make([]string, 0, len(p))
	for _, hop := range p {
		desc, err := doc.GetNodeByKeyHash(&hop.ID)
		if err != nil {
			return nil, err
		}
		names = append(names, desc.Name)
	}
	return names, nil
}

// ComposeSphinxPacket is used to compose Sphinx packets.
func (c *Client) ComposeSphinxPacket(request *Request) (pkt []byte, surbkey []byte, rtt time.Duration, err error) {
	pkt, surbkey, rtt, _, err = c.ComposeSphinxPacketWithRoute(request)
	return pkt, surbkey, rtt, err
}

// ComposeSphinxPacketWithRoute is ComposeSphinxPacket, additionally reporting
// the hops the packet was routed over. The route is diagnostic only: it is
// nil when the hops could not be named, which callers must read as unknown
// rather than as no hops.
func (c *Client) ComposeSphinxPacketWithRoute(request *Request) (pkt []byte, surbkey []byte, rtt time.Duration, route *Route, err error) {
	// Extract fields from the appropriate sub-struct
	var destinationIdHash *[32]byte
	var recipientQueueID []byte
	var requestPayload []byte
	var withSURB bool
	var surbID *[sConstants.SURBIDLength]byte

	if request.SendMessage != nil {
		destinationIdHash = request.SendMessage.DestinationIdHash
		recipientQueueID = request.SendMessage.RecipientQueueID
		requestPayload = request.SendMessage.Payload
		withSURB = request.SendMessage.WithSURB
		surbID = request.SendMessage.SURBID
	} else {
		return nil, nil, 0, nil, errors.New("request must have SendMessage")
	}

	if err := validateSendMessageRequest(destinationIdHash, recipientQueueID, requestPayload, c.geo.UserForwardPayloadLength); err != nil {
		return nil, nil, 0, nil, err
	}

	payload := make([]byte, c.geo.UserForwardPayloadLength)
	copy(payload, requestPayload)

	for attempt := 0; attempt < maxPathSelectionAttempts; attempt++ {
		// Check if we're shutting down to avoid races
		select {
		case <-c.HaltCh():
			return nil, nil, 0, nil, ErrShutdown
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

		fwdPath, then, err := c.makePath(recipientQueueID, destinationIdHash, surbID, now, true, gateway)
		if err != nil {
			return nil, nil, 0, nil, err
		}

		revPath := make([]*sphinx.PathHop, 0)
		if surbID != nil {
			if c.conn.queueID == nil {
				panic("sender queueID cannot be nil")
			}
			revPath, then, err = c.makePath(c.conn.queueID, destinationIdHash, surbID, then, false, gateway)
			if err != nil {
				return nil, nil, 0, nil, err
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
			rt := c.routeNames(fwdPath, revPath)
			if withSURB {
				payload := make([]byte, 2, 2+c.geo.SURBLength+len(requestPayload))
				payload[0] = 1 // Packet has a SURB.
				surb, k, err := c.sphinx.NewSURB(rand.Reader, revPath)
				if err != nil {
					return nil, nil, 0, nil, err
				}
				payload = append(payload, surb...)
				payload = append(payload, requestPayload...)

				blob := make([]byte, c.geo.ForwardPayloadLength)
				copy(blob, payload)

				pkt, err := c.sphinx.NewPacket(rand.Reader, fwdPath, blob)
				if err != nil {
					return nil, nil, 0, nil, err
				}
				return pkt, k, then.Sub(now), rt, err
			} else {
				blob := make([]byte, c.geo.ForwardPayloadLength)
				copy(blob, payload)

				pkt, err := c.sphinx.NewPacket(rand.Reader, fwdPath, blob)
				if err != nil {
					return nil, nil, 0, nil, err
				}
				return pkt, nil, then.Sub(now), rt, nil
			}
		}
	}
	return nil, nil, 0, nil, fmt.Errorf("ComposeSphinxPacket: path selection exceeded %d attempts", maxPathSelectionAttempts)
}

// SendCiphertext sends the ciphertext b to the recipient/provider, with a
// SURB identified by surbID, and returns the SURB decryption key and total
// round trip delay. Blocks until packet is sent on the wire.
func (c *Client) SendCiphertext(request *Request) ([]byte, time.Duration, error) {
	k, rtt, _, err := c.SendCiphertextWithRoute(request)
	return k, rtt, err
}

// SendCiphertextWithRoute is SendCiphertext, additionally reporting the hops
// the packet was routed over so that a caller may attribute a reply that never
// arrives to the nodes it would have traversed.
func (c *Client) SendCiphertextWithRoute(request *Request) ([]byte, time.Duration, *Route, error) {
	// Check that we have a valid send request
	if request.SendMessage == nil {
		return nil, 0, nil, errors.New("request must have SendMessage")
	}

	pkt, k, rtt, route, err := c.ComposeSphinxPacketWithRoute(request)
	if err != nil {
		// Don't panic on shutdown or other errors, return them gracefully
		return nil, 0, nil, err
	}
	err = c.conn.sendPacket(pkt)
	return k, rtt, route, err
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
		return nil, time.Time{}, newPKIError("client: makePath: no PKI document for current epoch")
	}

	src, dst, err := getSourceAndDestinationNodes(doc, gateway, destination, isForward)
	if err != nil {
		return nil, time.Time{}, err
	}

	rng := rand.NewMath()
	p, t, err := path.New(rng, c.cfg.SphinxGeometry, doc, recipient, src, dst, surbID, baseTime, true, isForward)
	if err != nil {
		return nil, time.Time{}, err
	}

	if len(p) == 0 {
		return nil, time.Time{}, fmt.Errorf("path selection returned zero hops")
	}

	return p, t, nil
}

// getSourceAndDestinationNodes retrieves the source and destination mix descriptors based on direction.
func getSourceAndDestinationNodes(doc *cpki.Document, gateway, destination *[32]byte, isForward bool) (*cpki.MixDescriptor, *cpki.MixDescriptor, error) {
	srcNode, dstNode := gateway, destination
	if !isForward {
		srcNode, dstNode = dstNode, srcNode
	}

	var src, dst *cpki.MixDescriptor
	var err error

	if isForward {
		src, err = doc.GetGatewayByKeyHash(srcNode)
		if err != nil {
			return nil, nil, newPKIError("client: failed to find source Gateway: %v", err)
		}
		dst, err = doc.GetServiceNodeByKeyHash(dstNode)
		if err != nil {
			return nil, nil, newPKIError("client: failed to find destination service node: %v", err)
		}
	} else {
		src, err = doc.GetServiceNodeByKeyHash(srcNode)
		if err != nil {
			return nil, nil, newPKIError("client: failed to find source service node: %v", err)
		}
		dst, err = doc.GetGatewayByKeyHash(dstNode)
		if err != nil {
			return nil, nil, newPKIError("client: failed to find destination gateway node: %v", err)
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

// ComposeSphinxPacketForQuery is used to compose Sphinx packets for channel queries.
func (c *Client) ComposeSphinxPacketForQuery(request *thin.SendChannelQuery, surbID *[sConstants.SURBIDLength]byte) (pkt []byte, surbkey []byte, rtt time.Duration, err error) {
	pkt, surbkey, rtt, _, err = c.ComposeSphinxPacketForQueryWithRoute(request, surbID)
	return pkt, surbkey, rtt, err
}

// ComposeSphinxPacketForQueryWithRoute is ComposeSphinxPacketForQuery,
// additionally reporting the hops the packet was routed over, under the same
// nil-means-unknown caveat.
func (c *Client) ComposeSphinxPacketForQueryWithRoute(request *thin.SendChannelQuery, surbID *[sConstants.SURBIDLength]byte) (pkt []byte, surbkey []byte, rtt time.Duration, route *Route, err error) {

	if len(request.Payload) > c.geo.UserForwardPayloadLength {
		return nil, nil, 0, nil, fmt.Errorf("ComposeSphinxPacketForQuery Payload field too large: %v > %v", len(request.Payload), c.geo.UserForwardPayloadLength)
	}

	for attempt := 0; attempt < maxPathSelectionAttempts; attempt++ {
		// Check if we're shutting down to avoid races
		select {
		case <-c.HaltCh():
			return nil, nil, 0, nil, ErrShutdown
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

		fwdPath, then, err := c.makePath(request.RecipientQueueID, request.DestinationIdHash, surbID, now, true, gateway)
		if err != nil {
			c.log.Errorf("ComposeSphinxPacketForQuery: c.makePath: fwdPath: err: %s", err.Error())
			return nil, nil, 0, nil, err
		}

		revPath := make([]*sphinx.PathHop, 0)
		if surbID != nil {
			if c.conn.queueID == nil {
				panic("sender queueID cannot be nil")
			}
			revPath, then, err = c.makePath(c.conn.queueID, request.DestinationIdHash, surbID, then, false, gateway)
			if err != nil {
				c.log.Errorf("ComposeSphinxPacketForQuery: c.makePath: revPath: err: %s", err.Error())
				return nil, nil, 0, nil, err
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
			rt := c.routeNames(fwdPath, revPath)
			payload := make([]byte, 2, 2+c.geo.SURBLength+len(request.Payload))
			payload[0] = 1 // Packet has a SURB.
			surb, k, err := c.sphinx.NewSURB(rand.Reader, revPath)
			if err != nil {
				return nil, nil, 0, nil, err
			}
			payload = append(payload, surb...)
			payload = append(payload, request.Payload...)

			blob := make([]byte, c.geo.ForwardPayloadLength)
			copy(blob, payload)

			pkt, err := c.sphinx.NewPacket(rand.Reader, fwdPath, blob)
			if err != nil {
				return nil, nil, 0, nil, err
			}
			return pkt, k, then.Sub(now), rt, err
		}
	}
	return nil, nil, 0, nil, fmt.Errorf("ComposeSphinxPacketForQuery: path selection exceeded %d attempts", maxPathSelectionAttempts)
}

// SendChannelQuery
func (c *Client) SendChannelQuery(sendQuery *thin.SendChannelQuery, surbID *[sConstants.SURBIDLength]byte) (surbKey []byte, rtt time.Duration, err error) {
	pkt, k, rtt, err := c.ComposeSphinxPacketForQuery(sendQuery, surbID)
	if err != nil {
		return nil, 0, err
	}
	err = c.conn.sendPacket(pkt)
	return k, rtt, err
}

// packet.go - Katzenpost server packet structure.
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

// Package packet implements the Katzenpost server side packet structure.
package packet

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/katzenpost/katzenpost/core/sphinx"
	"github.com/katzenpost/katzenpost/core/sphinx/commands"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/katzenpost/katzenpost/core/utils"
)

var (
	pktPool = sync.Pool{
		New: func() interface{} {
			return new(Packet)
		},
	}
	pktID uint64
)

type Packet struct {
	Geometry *geo.Geometry

	Raw     []byte
	Payload []byte

	// The parsed out routing commands.
	NextNodeHop *commands.NextNodeHop
	NodeDelay   *commands.NodeDelay
	Recipient   *commands.Recipient
	SurbReply   *commands.SURBReply

	ID         uint64
	Delay      time.Duration
	RecvAt     time.Time
	DispatchAt time.Time

	MustForward   bool
	MustTerminate bool

	rawPacketPool sync.Pool
}

// Set sets the Packet's internal components.
func (pkt *Packet) Set(payload []byte, cmds []commands.RoutingCommand) error {
	pkt.Payload = payload
	return pkt.splitCommands(cmds)
}

func (pkt *Packet) splitCommands(cmds []commands.RoutingCommand) error {
	for _, v := range cmds {
		switch cmd := v.(type) {
		case *commands.NextNodeHop:
			if pkt.NextNodeHop != nil {
				return newRedundantError(cmd)
			}
			pkt.NextNodeHop = cmd
		case *commands.NodeDelay:
			if pkt.NodeDelay != nil {
				return newRedundantError(cmd)
			}
			pkt.NodeDelay = cmd
		case *commands.Recipient:
			if pkt.Recipient != nil {
				return newRedundantError(cmd)
			}
			pkt.Recipient = cmd
		case *commands.SURBReply:
			if pkt.SurbReply != nil {
				return newRedundantError(cmd)
			}
			pkt.SurbReply = cmd
		default:
			return fmt.Errorf("unknown command type: %T", v)
		}
	}
	return nil
}

// CmdsToString returns an abbreviated list of the packet's routing commands,
// suitable for debugging.
func (pkt *Packet) CmdsToString() string {
	hasNextNodeHop := pkt.NextNodeHop != nil
	hasNodeDelay := pkt.NodeDelay != nil
	hasRecipient := pkt.Recipient != nil
	hasSURBReply := pkt.SurbReply != nil
	return fmt.Sprintf("NextNodeHop: %v NodeDelay: %v, Recipient: %v, SURBReply: %v", hasNextNodeHop, hasNodeDelay, hasRecipient, hasSURBReply)
}

// IsForward returns true iff the packet has routing commands indicating it is
// a forward packet destined for another hop.
func (pkt *Packet) IsForward() bool {
	return pkt.NextNodeHop != nil && pkt.NodeDelay != nil && pkt.Recipient == nil && pkt.SurbReply == nil
}

// IsToUser returns true iff the packet has routing commands indicating it is
// a forward packet destined for a local user.
func (pkt *Packet) IsToUser() bool {
	return pkt.NextNodeHop == nil && pkt.NodeDelay != nil && pkt.Recipient != nil && pkt.SurbReply == nil
}

// IsUnreliableToUser returns true iff the packet has routing commands
// indicating it is an unreliable forward packet destined for a local user.
func (pkt *Packet) IsUnreliableToUser() bool {
	return pkt.NextNodeHop == nil && pkt.NodeDelay == nil && pkt.Recipient != nil && pkt.SurbReply == nil
}

// IsSURBReply returns true iff the packet has routing commands indicating it
// is a SURB Reply destined for a local user.
func (pkt *Packet) IsSURBReply() bool {
	return pkt.NextNodeHop == nil && pkt.NodeDelay == nil && pkt.Recipient != nil && pkt.SurbReply != nil
}

// Dispose clears the packet structure and returns it to the allocation pool.
func (pkt *Packet) Dispose() {
	// Note: Calling Dispose() should happen for the common code paths, but
	// we rely on the GC just deallocating packets that happen to get leaked.
	//
	// In particular this will happen when connections get closed, since there
	// is no special effort made to clean out the various queues.

	// TODO/perf: Return the packet components to the various pools.
	pkt.disposeRaw()

	// Clear out the struct for reuse.
	// pkt.raw = nil // Cleared by pkt.disposeRaw()
	pkt.Payload = nil
	pkt.NextNodeHop = nil
	pkt.NodeDelay = nil
	pkt.Recipient = nil
	pkt.SurbReply = nil
	pkt.ID = 0
	pkt.Delay = 0
	pkt.RecvAt = time.Time{}
	pkt.DispatchAt = time.Time{}
	pkt.MustForward = false
	pkt.MustTerminate = false

	// Return the packet struct to the pool.
	pktPool.Put(pkt)
}

func (pkt *Packet) copyToRaw(b []byte) error {
	if len(b) != pkt.Geometry.PacketLength {
		// TODO: When we have actual large packets, handle them.
		errInfo := fmt.Sprintf("My Sphinx Geometry: %s\n%s\n", pkt.Geometry.String(),
			pkt.Geometry.Display())
		return fmt.Errorf("invalid Sphinx packet size: %v\n%s", len(b), errInfo)
	}

	// The common case of standard packet sizes uses a pool allocator
	// to store the raw packets.
	pkt.Raw = pkt.rawPacketPool.Get().([]byte)

	// Sanity check, just in case the pool allocator is doing something dumb.
	if len(pkt.Raw) != len(b) {
		panic("BUG: Pool allocated rawPkt has incorrect size")
	}

	// Copy the raw packet into pkt's buffer.
	copy(pkt.Raw, b)

	return nil
}

func (pkt *Packet) disposeRaw() {
	if len(pkt.Raw) == pkt.Geometry.PacketLength {
		utils.ExplicitBzero(pkt.Raw)
		pkt.rawPacketPool.Put(pkt.Raw) // nolint: megacheck
	}
	pkt.Raw = nil
}

// New allocates a new Packet, with the specified raw payload.
func New(raw []byte, g *geo.Geometry) (*Packet, error) {
	id := atomic.AddUint64(&pktID, 1)
	return NewWithID(raw, id, g)
}

// NewWithID allocates a new Packet, with the specified raw payload and ID.
// Most callers should use New, this exists to support serializing packets
// to external memory.
func NewWithID(raw []byte, id uint64, g *geo.Geometry) (*Packet, error) {
	v := pktPool.Get()
	pkt := v.(*Packet)
	pkt.Geometry = g
	pkt.ID = id
	pkt.rawPacketPool = sync.Pool{
		New: func() interface{} {
			b := make([]byte, pkt.Geometry.PacketLength)
			return b
		},
	}
	if err := pkt.copyToRaw(raw); err != nil {
		pkt.Dispose()
		return nil, err
	}
	return pkt, nil
}

func newRedundantError(cmd commands.RoutingCommand) error {
	return fmt.Errorf("redundant command: %T", cmd)
}

func ParseForwardPacket(pkt *Packet) ([]byte, []byte, error) {

	var hdrLength = pkt.Geometry.SphinxPlaintextHeaderLength + pkt.Geometry.SURBLength
	const (
		flagsPadding = 0
		flagsSURB    = 1
		reserved     = 0
	)

	// Sanity check the forward packet payload length.
	if len(pkt.Payload) != pkt.Geometry.ForwardPayloadLength {
		return nil, nil, fmt.Errorf("invalid payload length: %v", len(pkt.Payload))
	}

	// Parse the payload, which should be a valid BlockSphinxPlaintext.
	b := pkt.Payload
	if len(b) < hdrLength {
		return nil, nil, fmt.Errorf("truncated message block")
	}
	if b[1] != reserved {
		return nil, nil, fmt.Errorf("invalid message reserved: 0x%02x", b[1])
	}
	ct := b[hdrLength:]
	var surb []byte
	switch b[0] {
	case flagsPadding:
	case flagsSURB:
		surb = b[pkt.Geometry.SphinxPlaintextHeaderLength:hdrLength]
	default:
		return nil, nil, fmt.Errorf("invalid message flags: 0x%02x", b[0])
	}
	if len(ct) != pkt.Geometry.UserForwardPayloadLength {
		return nil, nil, fmt.Errorf("mis-sized user payload: %v", len(ct))
	}

	return ct, surb, nil
}

func NewPacketFromSURB(pkt *Packet, surb, payload []byte, geo *geo.Geometry) (*Packet, error) {
	if !pkt.IsToUser() {
		return nil, fmt.Errorf("invalid commands to generate a SURB reply")
	}

	// Pad out payloads to the full packet size.
	respPayload := make([]byte, pkt.Geometry.ForwardPayloadLength)
	switch {
	case len(payload) == 0:
	case len(payload) > pkt.Geometry.ForwardPayloadLength:
		return nil, fmt.Errorf("oversized response payload: %v", len(payload))
	default:
		copy(respPayload, payload)
	}

	// Build a response packet using a SURB.
	//
	// TODO/perf: This is a crypto operation that is paralleizable, and
	// could be handled by the crypto worker(s), since those are allocated
	// based on hardware acceleration considerations.  However the forward
	// packet processing doesn't constantly utilize the AES-NI units due
	// to the non-AEZ components of a Sphinx Unwrap operation.

	pkt.Geometry = geo
	s, err := sphinx.FromGeometry(pkt.Geometry)
	if err != nil {
		return nil, err
	}
	rawRespPkt, firstHop, err := s.NewPacketFromSURB(surb, respPayload)
	if err != nil {
		return nil, err
	}

	// Build the command vector for the SURB-ACK
	cmds := make([]commands.RoutingCommand, 0, 2)

	nextHopCmd := new(commands.NextNodeHop)
	copy(nextHopCmd.ID[:], firstHop[:])
	cmds = append(cmds, nextHopCmd)

	nodeDelayCmd := new(commands.NodeDelay)
	nodeDelayCmd.Delay = pkt.NodeDelay.Delay
	cmds = append(cmds, nodeDelayCmd)

	// Assemble the response packet.
	respPkt, err := New(rawRespPkt, geo)
	if err != nil {
		return nil, err
	}
	respPkt.Geometry = pkt.Geometry
	err = respPkt.Set(nil, cmds)
	if err != nil {
		return nil, err
	}

	respPkt.RecvAt = pkt.RecvAt
	// XXX: This should probably fudge the delay to account for processing
	// time.
	respPkt.Delay = time.Duration(nodeDelayCmd.Delay) * time.Millisecond
	respPkt.MustForward = true
	respPkt.rawPacketPool = sync.Pool{
		New: func() interface{} {
			b := make([]byte, pkt.Geometry.PacketLength)
			return b
		},
	}

	return respPkt, nil
}

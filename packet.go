// packet.go - Katzenpost server packet allocator.
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

package server

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/katzenpost/core/constants"
	"github.com/katzenpost/core/sphinx/commands"
	"github.com/katzenpost/core/utils"
)

var (
	pktPool = sync.Pool{
		New: func() interface{} {
			return new(packet)
		},
	}
	rawPacketPool = sync.Pool{
		New: func() interface{} {
			return make([]byte, constants.PacketLength)
		},
	}
	pktID uint64
)

type packet struct {
	raw     []byte
	payload []byte
	cmds    []commands.RoutingCommand

	// The parsed out routing commands.
	nextNodeHop *commands.NextNodeHop
	nodeDelay   *commands.NodeDelay
	recipient   *commands.Recipient
	surbReply   *commands.SURBReply

	id         uint64
	delay      time.Duration
	recvAt     time.Duration
	dispatchAt time.Duration

	mustForward   bool
	mustTerminate bool
}

func (pkt *packet) splitCommands() error {
	newRedundantError := func(cmd commands.RoutingCommand) error {
		// The packet may be more screwed up, but the splitting returns on
		// first error.
		return fmt.Errorf("redundant command: %t", cmd)
	}

	for _, v := range pkt.cmds {
		switch cmd := v.(type) {
		case *commands.NextNodeHop:
			if pkt.nextNodeHop != nil {
				return newRedundantError(cmd)
			}
			pkt.nextNodeHop = cmd
		case *commands.NodeDelay:
			if pkt.nodeDelay != nil {
				return newRedundantError(cmd)
			}
			pkt.nodeDelay = cmd
		case *commands.Recipient:
			if pkt.recipient != nil {
				return newRedundantError(cmd)
			}
			pkt.recipient = cmd
		case *commands.SURBReply:
			if pkt.surbReply != nil {
				return newRedundantError(cmd)
			}
			pkt.surbReply = cmd
		default:
			return fmt.Errorf("unknown command type: %t", v)
		}
	}
	return nil
}

func (pkt *packet) cmdsToString() string {
	hasNextNodeHop := pkt.nextNodeHop != nil
	hasNodeDelay := pkt.nodeDelay != nil
	hasRecipient := pkt.recipient != nil
	hasSURBReply := pkt.surbReply != nil
	return fmt.Sprintf("NextNodeHop: %v NodeDelay: %v, Recipient: %v, SURBReply: %v", hasNextNodeHop, hasNodeDelay, hasRecipient, hasSURBReply)
}

func (pkt *packet) isForward() bool {
	return pkt.nextNodeHop != nil && pkt.nodeDelay != nil && pkt.recipient == nil && pkt.surbReply == nil
}

func (pkt *packet) isToUser() bool {
	return pkt.nextNodeHop == nil && pkt.nodeDelay != nil && pkt.recipient != nil && pkt.surbReply == nil
}

func (pkt *packet) isSURBReply() bool {
	return pkt.nextNodeHop == nil && pkt.nodeDelay == nil && pkt.recipient != nil && pkt.surbReply != nil
}

func (pkt *packet) copyToRaw(b []byte) error {
	if len(b) != constants.PacketLength {
		// TODO: When we have actual large packets, handle them.
		return fmt.Errorf("invalid Sphinx packet size: %v", len(b))
	}

	// The common case of standard packet sizes uses a pool allocator
	// to store the raw packets.
	pkt.raw = rawPacketPool.Get().([]byte)

	// Sanity check, just in case the pool allocator is doing something dumb.
	if len(pkt.raw) != len(b) {
		panic("BUG: Pool allocated rawPkt has incorrect size")
	}

	// Copy the raw packet into pkt's buffer.
	copy(pkt.raw, b)

	return nil
}

func (pkt *packet) disposeRaw() {
	if len(pkt.raw) == constants.PacketLength {
		utils.ExplicitBzero(pkt.raw)
		rawPacketPool.Put(pkt.raw)
	}
	pkt.raw = nil
}

func newPacket() *packet {
	v := pktPool.Get()
	pkt := v.(*packet)
	pkt.id = atomic.AddUint64(&pktID, 1) // Diagnostic only, wrapping is fine.
	return pkt
}

func (pkt *packet) dispose() {
	// Note: Calling dispose() should happen for the common code paths, but
	// we rely on the GC just deallocating packets that happen to get leaked.
	//
	// In particular this will happen when connections get closed, since there
	// is no special effort made to clean out the various queues.

	// TODO/perf: Return the packet components to the various pools.
	pkt.disposeRaw()

	// Clear out the struct for reuse.
	// pkt.rawPkt = nil // Cleared by pkt.disposeRaw()
	pkt.payload = nil
	pkt.cmds = nil
	pkt.nextNodeHop = nil
	pkt.nodeDelay = nil
	pkt.recipient = nil
	pkt.surbReply = nil
	pkt.id = 0
	pkt.delay = 0
	pkt.recvAt = 0
	pkt.dispatchAt = 0
	pkt.mustForward = false
	pkt.mustTerminate = false

	// Return the packet struct to the pool.
	pktPool.Put(pkt)
}

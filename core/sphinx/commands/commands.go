// commands.go - Per-hop Routing Info Commands.
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

// Package commands implements the Sphinx Packet Format per-hop routing info
// commands.
package commands

import (
	"encoding/binary"
	"errors"

	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/katzenpost/katzenpost/core/sphinx/internal/crypto"
	"github.com/katzenpost/katzenpost/core/utils"
)

const (

	// Generic commands.
	null        commandID = 0x00
	nextNodeHop commandID = 0x01
	recipient   commandID = 0x02
	surbReply   commandID = 0x03

	// Implementation defined commands.
	nodeDelay commandID = 0x80
)

var errInvalidCommand = errors.New("sphinx: invalid per-hop command")

type commandID byte

// RoutingCommand is the common interface exposed by all per-hop routing
// command structures.
type RoutingCommand interface {
	// ToBytes appends the serialized command to slice b, and returns the
	// resulting slice.
	ToBytes(b []byte) []byte
}

// FromBytes deserializes the first per-hop routing command in the buffer b,
// returning a RoutingCommand and the remaining bytes (if any), or an error.
func FromBytes(b []byte, g *geo.Geometry) (cmd RoutingCommand, rest []byte, err error) {
	if len(b) == 0 {
		// Treat a 0 length command as a null command.
		return
	}

	id := b[0]
	if len(b) == 1 {
		// null can have 0 body, and requires special handling.
		if commandID(id) != null {
			err = errInvalidCommand
		}
		return
	}
	b = b[1:]

	switch commandID(id) {
	case null:
		// The null command, being the terminal command is a special case.
		if len(b) > 0 {
			if !utils.CtIsZero(b) {
				err = errInvalidCommand
				return
			}
		}
	case nextNodeHop:
		cmd, rest, err = nextNodeHopFromBytes(b, g)
	case recipient:
		cmd, rest, err = recipeientFromBytes(b, g)
	case surbReply:
		cmd, rest, err = surbReplyFromBytes(b, g)
	case nodeDelay:
		cmd, rest, err = nodeDelayFromBytes(b)
	default:
		err = errInvalidCommand
	}
	return
}

// NextNodeHop is a de-serialized Sphinx next_node command.
type NextNodeHop struct {
	ID  [geo.NodeIDLength]byte
	MAC [crypto.MACLength]byte
}

// ToBytes appends the serialized NextNodeHop to slice b, and returns the
// resulting slice.
func (cmd *NextNodeHop) ToBytes(b []byte) []byte {
	b = append(b, byte(nextNodeHop))
	b = append(b, cmd.ID[:]...)
	b = append(b, cmd.MAC[:]...)
	return b
}

func nextNodeHopFromBytes(b []byte, g *geo.Geometry) (cmd RoutingCommand, rest []byte, err error) {
	if len(b) < g.NextNodeHopLength-1 {
		err = errInvalidCommand
		return
	}
	rest = b[g.NextNodeHopLength-1:]

	r := new(NextNodeHop)
	copy(r.ID[:], b[:g.NodeIDLength])
	copy(r.MAC[:], b[g.NodeIDLength:])
	cmd = r
	return
}

// Recipient is a de-serialized Sphinx recipient command.
type Recipient struct {
	ID [geo.RecipientIDLength]byte
}

// ToBytes appends the serialized Recipeient to slice b, and returns the
// resulting slice.
func (cmd *Recipient) ToBytes(b []byte) []byte {
	b = append(b, byte(recipient))
	b = append(b, cmd.ID[:]...)
	return b
}

func recipeientFromBytes(b []byte, g *geo.Geometry) (cmd RoutingCommand, rest []byte, err error) {

	// recipientLength is the length of a Recipient command in bytes.
	recipientLength := 1 + g.RecipientIDLength

	if len(b) < recipientLength-1 {
		err = errInvalidCommand
		return
	}
	rest = b[recipientLength-1:]

	r := new(Recipient)
	copy(r.ID[:], b[:g.RecipientIDLength])
	cmd = r
	return
}

// SURBReply is a de-serialized Sphinx surb-reply command.
type SURBReply struct {
	ID [geo.SURBIDLength]byte
}

// ToBytes appends the serialized SURBReply to slice b, and returns the
// resulting slice.
func (cmd *SURBReply) ToBytes(b []byte) []byte {
	b = append(b, byte(surbReply))
	b = append(b, cmd.ID[:]...)
	return b
}

func surbReplyFromBytes(b []byte, g *geo.Geometry) (cmd RoutingCommand, rest []byte, err error) {

	// surbReplyLength is the length of a SURBReply command in bytes.
	surbReplyLength := 1 + g.SURBIDLength

	if len(b) < surbReplyLength-1 {
		err = errInvalidCommand
		return
	}
	rest = b[surbReplyLength-1:]

	r := new(SURBReply)
	copy(r.ID[:], b[:g.SURBIDLength])
	cmd = r
	return
}

// NodeDelay is a de-serialized Sphinx mix_delay command.
type NodeDelay struct {
	Delay uint32
}

// ToBytes appends the serialized NodeDelay to slice b, and returns the
// resulting slice.
func (cmd *NodeDelay) ToBytes(b []byte) []byte {
	var tmp [4]byte
	b = append(b, byte(nodeDelay))
	binary.BigEndian.PutUint32(tmp[:], cmd.Delay)
	b = append(b, tmp[:]...)
	return b
}

func nodeDelayFromBytes(b []byte) (cmd RoutingCommand, rest []byte, err error) {
	// nodeDelayLength is the length of a NodeDelay command in bytes.
	nodeDelayLength := 1 + 4

	if len(b) < nodeDelayLength-1 {
		err = errInvalidCommand
		return
	}
	rest = b[nodeDelayLength-1:]

	r := new(NodeDelay)
	r.Delay = binary.BigEndian.Uint32(b[:4])
	cmd = r
	return
}

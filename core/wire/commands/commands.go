// SPDX-FileCopyrightText: Copyright (C) 2017  David Anthony Stainton, Yawning Angel
// SPDX-License-Identifier: AGPL-3.0-only

// Wire protocol commands.
package commands

import (
	"encoding/binary"
	"errors"

	"github.com/katzenpost/hpqc/sign"

	"github.com/katzenpost/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/katzenpost/katzenpost/core/utils"
	wireconstants "github.com/katzenpost/katzenpost/core/wire/constants"
)

var (
	errInvalidCommand = errors.New("wire: invalid wire protocol command")
)

type (
	commandID   byte
	messageType byte
)

// Command is the common interface exposed by all message command structures.
type Command interface {
	// ToBytes serializes the command and returns the resulting slice.
	ToBytes() []byte
}

// Commands encapsulates all of the wire protocol commands so that it can
// pass around a sphinx geometry where needed.
type Commands struct {
	geo                *geo.Geometry
	pkiSignatureScheme sign.Scheme
}

// NewCommands returns a Commands given a sphinx geometry.
func NewCommands(geo *geo.Geometry, pkiSignatureScheme sign.Scheme) *Commands {

	c := &Commands{
		geo:                geo,
		pkiSignatureScheme: pkiSignatureScheme,
	}
	_ = c.maxMessageLenServerToClient()
	_ = c.maxMessageLenClientToServer()
	return c
}

func (c *Commands) messageMsgPaddingLength() int {
	return constants.SURBIDLength + c.geo.SphinxPlaintextHeaderLength + c.geo.SURBLength + c.geo.PayloadTagLength
}

func (c *Commands) messageMsgLength() int {
	return messageBaseLength + c.messageMsgPaddingLength()
}

func (c *Commands) maxMessageLenServerToClient() int {
	t := cmdOverhead + c.messageMsgLength() + c.geo.UserForwardPayloadLength
	if t > wireconstants.MaxMsgLen {
		panic("cannot set maxMessageLenServerToClient to exceed MaxMsgLen")
	}
	return t
}

func (c *Commands) maxMessageLenClientToServer() int {
	t := cmdOverhead + c.geo.PacketLength
	if t > wireconstants.MaxMsgLen {
		panic("cannot set maxMessageLenClientToServer to exceed MaxMsgLen")
	}
	return t
}

func (c *Commands) maxMessageLen(cmd Command) int {
	switch cmd.(type) {
	case *NoOp, *SendPacket, *Disconnect, *RetrieveMessage, *GetConsensus, *SendRetrievePacket:
		// These are client to server commands
		return c.maxMessageLenClientToServer()
	case *Message, *MessageACK, *MessageEmpty, *SendRetrievePacketReply:
		// These are server to client commands
		return c.maxMessageLenServerToClient()
	default:
		panic("unhandled command type passed to maxMessageLen")
	}
}

// NoOp is a de-serialized noop command.
type NoOp struct {
	Cmds *Commands
}

// ToBytes serializes the NoOp and returns the resulting slice.
func (c *NoOp) ToBytes() []byte {
	out := make([]byte, cmdOverhead)
	out[0] = byte(noOp)
	return padToMaxCommandSize(out, c.Cmds.maxMessageLen(c))
}

// Disconnect is a de-serialized disconnect command.
type Disconnect struct {
	Cmds *Commands
}

// ToBytes serializes the Disconnect and returns the resulting slice.
func (c *Disconnect) ToBytes() []byte {
	out := make([]byte, cmdOverhead)
	out[0] = byte(disconnect)
	return padToMaxCommandSize(out, c.Cmds.maxMessageLen(c))
}

// SendRetrievePacket is a command that sends a message
// or decoy and also retrieves a new message or decoy.
type SendRetrievePacket struct {
	Geo  *geo.Geometry
	Cmds *Commands

	SphinxPacket []byte
}

func (c *SendRetrievePacket) ToBytes() []byte {
	out := make([]byte, cmdOverhead, cmdOverhead+len(c.SphinxPacket))
	out[0] = byte(sendRetrievePacket)
	binary.BigEndian.PutUint32(out[2:6], uint32(len(c.SphinxPacket)))
	out = append(out, c.SphinxPacket...)
	return padToMaxCommandSize(out, c.Cmds.maxMessageLen(c))
}

func sendRetrievePacketFromBytes(b []byte, cmds *Commands) (Command, error) {
	r := new(SendRetrievePacket)
	r.SphinxPacket = make([]byte, 0, len(b))
	r.SphinxPacket = append(r.SphinxPacket, b...)
	r.Cmds = cmds
	r.Geo = cmds.geo
	return r, nil
}

// SendRetrievePacketReply is the reply command for a previously
// sent `SendRetrievePacket`
type SendRetrievePacketReply struct {
	Cmds *Commands
	Geo  *geo.Geometry

	SURBID  [constants.SURBIDLength]byte
	Payload []byte
}

func (c *SendRetrievePacketReply) ToBytes() []byte {
	out := make([]byte, cmdOverhead+constants.SURBIDLength, cmdOverhead+constants.SURBIDLength+len(c.Payload))
	out[0] = byte(sendRetrievePacketReply)
	binary.BigEndian.PutUint32(out[2:6], uint32(constants.SURBIDLength+len(c.Payload)))
	copy(out[cmdOverhead:cmdOverhead+constants.SURBIDLength], c.SURBID[:])
	out = append(out, c.Payload...)
	return padToMaxCommandSize(out, c.Cmds.maxMessageLen(c))
}

func sendRetrievePacketReplyFromBytes(b []byte, cmds *Commands) (Command, error) {
	c := new(SendRetrievePacketReply)
	copy(c.SURBID[:], b[:constants.SURBIDLength])
	c.Payload = make([]byte, len(b[constants.SURBIDLength:]))
	copy(c.Payload, b[constants.SURBIDLength:])
	c.Cmds = cmds
	c.Geo = cmds.geo
	return c, nil
}

// FromBytes de-serializes the command in the buffer b, returning a Command or
// an error.
func (c *Commands) FromBytes(b []byte) (Command, error) {
	if len(b) < cmdOverhead {
		return nil, errInvalidCommand
	}

	// Parse the common header.
	id := b[0]
	if b[1] != 0 {
		return nil, errInvalidCommand
	}
	cmdLen := binary.BigEndian.Uint32(b[2:6])
	b = b[cmdOverhead:]
	if uint32(len(b)) < cmdLen {
		return nil, errInvalidCommand
	}
	padding := b[cmdLen:]

	// Ensure that it is zero padded.
	if !utils.CtIsZero(padding) {
		return nil, errInvalidCommand
	}

	// Just handle the commands with no payload inline.
	if cmdLen == 0 {
		switch commandID(id) {
		case noOp:
			return &NoOp{
				Cmds: c,
			}, nil
		case disconnect:
			return &Disconnect{
				Cmds: c,
			}, nil
		case sendPacket, postDescriptor, sendRetrievePacket, sendRetrievePacketReply:
			// Shouldn't happen, but the caller should reject this, not the
			// de-serialization.
		default:
			return nil, errInvalidCommand
		}
	}

	// Handle the commands that require actual parsing.
	b = b[:cmdLen]
	switch commandID(id) {
	case sendRetrievePacket:
		return sendRetrievePacketFromBytes(b, c)
	case sendRetrievePacketReply:
		return sendRetrievePacketReplyFromBytes(b, c)
	case sendPacket:
		return sendPacketFromBytes(b, c)
	case retreiveMessage:
		return retreiveMessageFromBytes(b, c)
	case message:
		return c.messageFromBytes(b, c)
	case getConsensus:
		return getConsensusFromBytes(b, c)
	case consensus:
		return consensusFromBytes(b)
	case postDescriptor:
		return postDescriptorFromBytes(b)
	case postDescriptorStatus:
		return postDescriptorStatusFromBytes(b)
	case getVote:
		return getVoteFromBytes(b, c.pkiSignatureScheme)
	case vote:
		return voteFromBytes(b, c.pkiSignatureScheme)
	case voteStatus:
		return voteStatusFromBytes(b)
	case certificate:
		return certFromBytes(b, c.pkiSignatureScheme)
	case certStatus:
		return certStatusFromBytes(b)
	case reveal:
		return revealFromBytes(b, c.pkiSignatureScheme)
	case revealStatus:
		return revealStatusFromBytes(b)
	case sig:
		return sigFromBytes(b, c.pkiSignatureScheme)
	case sigStatus:
		return sigStatusFromBytes(b)
	default:
		return nil, errInvalidCommand
	}
}

// padToMaxCommandSize takes a slice of bytes representing a serialized command and pads it to maxCommandSize.
func padToMaxCommandSize(data []byte, maxMessageLen int) []byte {
	paddingSize := maxMessageLen - len(data)
	if paddingSize <= 0 {
		return data
	}

	padding := make([]byte, paddingSize)
	return append(data, padding...)
}

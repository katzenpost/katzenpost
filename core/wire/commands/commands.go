// SPDX-FileCopyrightText: Copyright (C) 2017  David Anthony Stainton, Yawning Angel
// SPDX-License-Identifier: AGPL-3.0-only

// Wire protocol commands.
package commands

import (
	"encoding/binary"
	"errors"

	"github.com/katzenpost/hpqc/nike"
	"github.com/katzenpost/hpqc/sign"

	"github.com/katzenpost/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/katzenpost/katzenpost/core/utils"
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

	// Length returns the length in bytes of the given command.
	Length() int
}

// Commands encapsulates all of the wire protocol commands so that it can
// pass around a sphinx geometry where needed.
type Commands struct {
	geo                         *geo.Geometry
	pkiSignatureScheme          sign.Scheme
	replicaNikeScheme           nike.Scheme
	clientToServerCommands      []Command
	serverToClientCommands      []Command
	MaxMessageLenServerToClient int
	MaxMessageLenClientToServer int
	shouldPad                   bool
}

// NewMixnetCommands creates a Commands instance suitale to be used by mixnet nodes.
func NewMixnetCommands(geo *geo.Geometry) *Commands {
	c := &Commands{
		geo:                geo,
		pkiSignatureScheme: nil,
		shouldPad:          true,
	}
	c.clientToServerCommands = []Command{
		&NoOp{}, &SendPacket{
			Cmds: c,
		}, &Disconnect{}, &RetrieveMessage{}, &GetConsensus{}, &SendRetrievePacket{
			Geo:  geo,
			Cmds: c,
		},
	}
	c.serverToClientCommands = []Command{
		&Message{
			Geo:  geo,
			Cmds: c,
		}, &MessageACK{
			Geo:  geo,
			Cmds: c,
		}, &MessageEmpty{
			Cmds: c,
		}, &SendRetrievePacketReply{
			Geo:  geo,
			Cmds: c,
		},
	}
	c.MaxMessageLenClientToServer = c.calcMaxMessageLenClientToServer()
	c.MaxMessageLenServerToClient = c.calcMaxMessageLenServerToClient()
	return c
}

// NewStorageReplicaCommands creates a Commands instance suitale to be used by storage replica nodes.
func NewStorageReplicaCommands(geo *geo.Geometry, scheme nike.Scheme) *Commands {
	c := &Commands{
		geo:                geo,
		pkiSignatureScheme: nil,
		replicaNikeScheme:  scheme,
	}
	payload := make([]byte, geo.PacketLength) // XXX TODO(David): Pick a more precise size.
	c.serverToClientCommands = []Command{
		&ReplicaMessage{
			Geo:    geo,
			Cmds:   c,
			Scheme: scheme,

			SenderEPubKey: make([]byte, HybridKeySize(scheme)),
			DEK:           &[32]byte{},
			Ciphertext:    payload,
		},
		&ReplicaMessageReply{
			Cmds: c,
		},
		&ReplicaRead{
			Cmds: c,
		},
		&ReplicaReadReply{
			Cmds: c,
			Geo:  geo,
		},
		&ReplicaWrite{
			Cmds: c,
		},
		&ReplicaWriteReply{
			Cmds: c,
		},
	}
	c.clientToServerCommands = c.serverToClientCommands
	c.shouldPad = true
	c.MaxMessageLenClientToServer = c.calcMaxMessageLenClientToServer()
	c.MaxMessageLenServerToClient = c.calcMaxMessageLenServerToClient()
	return c
}

// NewPKICommands creates a Commands instance suitale to be used by PKI nodes.
func NewPKICommands(pkiSignatureScheme sign.Scheme) *Commands {
	const defaultReplicaDescriptorSize = 123
	c := &Commands{
		geo:                    nil,
		pkiSignatureScheme:     pkiSignatureScheme,
		clientToServerCommands: nil,
		serverToClientCommands: nil,
		shouldPad:              false,

		// XXX arbitrarily set to some large max
		// such that we have a reasonable chance
		// of our Vote/Consensus commands fitting within this size maximum.
		// These larger commands contain the entire PKI document and can be
		// very large depending on the ciphersuites, the Sphinx KEM/NIKE and PKI Signature scheme.
		// Increase the size if your PKI doc doesn't fit.
		MaxMessageLenClientToServer: 500000,
		MaxMessageLenServerToClient: 500000,
	}
	return c
}

func (c *Commands) MaxCommandSize() int {
	if c.MaxMessageLenServerToClient > c.MaxMessageLenClientToServer {
		return c.MaxMessageLenServerToClient
	}
	return c.MaxMessageLenClientToServer
}

func (c *Commands) calcMaxMessageLenServerToClient() int {
	m := 0
	for _, c := range c.serverToClientCommands {
		if c.Length() > m {
			m = c.Length()
		}
	}
	return m
}

func (c *Commands) calcMaxMessageLenClientToServer() int {
	m := 0
	for _, c := range c.clientToServerCommands {
		if c.Length() > m {
			m = c.Length()
		}
	}
	return m
}

// padToMaxCommandSize takes a slice of bytes representing a serialized command and pads it to maxCommandSize.
func (c *Commands) padToMaxCommandSize(data []byte, isUpstream bool) []byte {
	var maxMessageLen int
	if isUpstream {
		maxMessageLen = c.MaxMessageLenClientToServer
	} else {
		maxMessageLen = c.MaxMessageLenServerToClient
	}
	if maxMessageLen == 0 {
		return data
	}
	paddingSize := maxMessageLen - len(data)
	if paddingSize <= 0 {
		return data
	}

	padding := make([]byte, paddingSize)
	return append(data, padding...)
}

// NoOp is a de-serialized noop command.
type NoOp struct {
	Cmds *Commands
}

// ToBytes serializes the NoOp and returns the resulting slice.
func (c *NoOp) ToBytes() []byte {
	out := make([]byte, cmdOverhead)
	out[0] = byte(noOp)
	return c.Cmds.padToMaxCommandSize(out, true)
}

func (c *NoOp) Length() int {
	return cmdOverhead
}

// Disconnect is a de-serialized disconnect command.
type Disconnect struct {
	Cmds *Commands
}

// ToBytes serializes the Disconnect and returns the resulting slice.
func (c *Disconnect) ToBytes() []byte {
	out := make([]byte, cmdOverhead)
	out[0] = byte(disconnect)
	return c.Cmds.padToMaxCommandSize(out, true)
}

func (c *Disconnect) Length() int {
	return cmdOverhead
}

// SendRetrievePacket is a command that sends a message
// or decoy and also retrieves a new message or decoy.
type SendRetrievePacket struct {
	Geo  *geo.Geometry
	Cmds *Commands

	SphinxPacket []byte
}

func (c *SendRetrievePacket) ToBytes() []byte {
	if len(c.SphinxPacket) != c.Geo.PacketLength {
		panic("SphinxPacket must be set to Geo.PacketLength")
	}
	out := make([]byte, cmdOverhead, cmdOverhead+len(c.SphinxPacket))
	out[0] = byte(sendRetrievePacket)
	binary.BigEndian.PutUint32(out[2:6], uint32(len(c.SphinxPacket)))
	out = append(out, c.SphinxPacket...)
	return c.Cmds.padToMaxCommandSize(out, true)
}

func (c *SendRetrievePacket) Length() int {
	return cmdOverhead + c.Geo.PacketLength
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
	return c.Cmds.padToMaxCommandSize(out, false)
}

func (c *SendRetrievePacketReply) Length() int {
	return cmdOverhead + constants.SURBIDLength + c.Geo.UserForwardPayloadLength
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
	case postReplicaDescriptor:
		return postReplicaDescriptorFromBytes(b)
	case postReplicaDescriptorStatus:
		return postReplicaDescriptorStatusFromBytes(b)
	case replicaRead:
		return replicaReadFromBytes(b, c)
	case replicaReadReply:
		return replicaReadReplyFromBytes(b, c)
	case replicaWrite:
		return replicaWriteFromBytes(b, c)
	case replicaWriteReply:
		return replicaWriteReplyFromBytes(b, c)
	case replicaMessage:
		return replicaMessageFromBytes(b, c)
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

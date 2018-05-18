// commands.go - Wire protocol commands.
// Copyright (C) 2017  David Anthony Stainton, Yawning Angel
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

package commands

import (
	"encoding/binary"
	"errors"

	"github.com/katzenpost/core/constants"
	"github.com/katzenpost/core/crypto/eddsa"
	"github.com/katzenpost/core/sphinx"
	sphinxConstants "github.com/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/core/utils"
)

const (
	cmdOverhead = 1 + 1 + 4

	retreiveMessageLength   = 4
	messageBaseLength       = 1 + 1 + 4
	messageACKLength        = messageBaseLength + sphinxConstants.SURBIDLength
	messageMsgLength        = messageBaseLength + messageMsgPaddingLength
	messageMsgPaddingLength = sphinxConstants.SURBIDLength + constants.SphinxPlaintextHeaderLength + sphinx.SURBLength + sphinx.PayloadTagLength
	messageEmptyLength      = messageACKLength + sphinx.PayloadTagLength + constants.ForwardPayloadLength

	getConsensusLength  = 8
	consensusBaseLength = 1

	postDescriptorStatusLength = 1
	postDescriptorLength       = 8

	voteOverhead     = 8 + eddsa.PublicKeySize
	voteStatusLength = 1

	messageTypeMessage messageType = 0
	messageTypeACK     messageType = 1
	messageTypeEmpty   messageType = 2

	// Generic commands.
	noOp       commandID = 0
	disconnect commandID = 1
	sendPacket commandID = 2

	// Implementation defined commands.
	retreiveMessage      commandID = 16
	message              commandID = 17
	getConsensus         commandID = 18
	consensus            commandID = 19
	postDescriptor       commandID = 20
	postDescriptorStatus commandID = 21
	vote                 commandID = 22
	voteStatus           commandID = 23
	getVote              commandID = 24

	// ConsensusOk signifies that the GetConsensus request has completed
	// successfully.
	ConsensusOk = 0

	// ConsensusNotFound signifies that the document document corresponding
	// to the epoch in the GetConsensus was not found, but retrying later
	// may be successful.
	ConsensusNotFound = 1

	// ConsensusGone signifies that the document corresponding to the epoch
	// in the GetConsensus was not found, and that retrying later will
	// not be successful.
	ConsensusGone = 2

	// DescriptorOk signifies that the PostDescriptor request has completed
	// succcessfully.
	DescriptorOk = 0

	// DescriptorInvalid signifies that the PostDescriptor request has failed
	// due to an unspecified error.
	DescriptorInvalid = 1

	// DescriptorConflict signifies that the PostDescriptor request has
	// failed due to the uploaded descriptor conflicting with a previously
	// uploaded descriptor.
	DescriptorConflict = 2

	// DescriptorForbidden signifies that the PostDescriptor request has
	// failed due to an authentication error.
	DescriptorForbidden = 3

	// VoteOk signifies that the vote was accepted by the peer.
	VoteOk = 0

	// VoteTooLate signifies that the vote was too late.
	VoteTooLate = 1

	// VoteTooEarly signifies that the vote was too late.
	VoteTooEarly = 2

	// VoteNotAuthorized signifies that the voting entity's key is not white-listed.
	VoteNotAuthorized = 3

	// VoteNotSigned signifies that the vote payload failed signature verification.
	VoteNotSigned = 4

	// VoteMalformed signifies that the vote payload was invalid.
	VoteMalformed = 5

	// VoteAlreadyReceived signifies that the vote from that peer was already received.
	VoteAlreadyReceived = 6

	// VoteNotFound signifies that the vote was not found.
	VoteNotFound = 7
)

var errInvalidCommand = errors.New("wire: invalid wire protocol command")

type (
	commandID   byte
	messageType byte
)

// Command is the common interface exposed by all message command structures.
type Command interface {
	// ToBytes serializes the command and returns the resulting slice.
	ToBytes() []byte
}

// NoOp is a de-serialized noop command.
type NoOp struct{}

// ToBytes serializes the NoOp and returns the resulting slice.
func (c *NoOp) ToBytes() []byte {
	out := make([]byte, cmdOverhead)
	out[0] = byte(noOp)
	return out
}

// GetConsensus is a de-serialized get_consensus command.
type GetConsensus struct {
	Epoch uint64
}

// ToBytes serializes the GetConsensus and returns the resulting byte slice.
func (c *GetConsensus) ToBytes() []byte {
	out := make([]byte, cmdOverhead+getConsensusLength)
	out[0] = byte(getConsensus)
	binary.BigEndian.PutUint32(out[2:6], getConsensusLength)
	binary.BigEndian.PutUint64(out[6:14], c.Epoch)
	return out
}

func getConsensusFromBytes(b []byte) (Command, error) {
	if len(b) != getConsensusLength {
		return nil, errInvalidCommand
	}

	r := new(GetConsensus)
	r.Epoch = binary.BigEndian.Uint64(b[0:8])
	return r, nil
}

// GetVote is a de-serialized get_vote command.
type GetVote struct {
	Epoch     uint64
	PublicKey *eddsa.PublicKey
}

func (v *GetVote) ToBytes() []byte {
	out := make([]byte, cmdOverhead+8, cmdOverhead+voteOverhead)
	out[0] = byte(getVote)
	binary.BigEndian.PutUint32(out[2:6], voteOverhead)
	binary.BigEndian.PutUint64(out[6:14], v.Epoch)
	out = append(out, v.PublicKey.Bytes()...)
	return out
}

func getVoteFromBytes(b []byte) (Command, error) {
	if len(b) != voteOverhead {
		return nil, errInvalidCommand
	}
	r := new(GetVote)
	r.Epoch = binary.BigEndian.Uint64(b[0:8])
	r.PublicKey = new(eddsa.PublicKey)
	err := r.PublicKey.FromBytes(b[8:40])
	if err != nil {
		return nil, err
	}
	return r, nil
}

// Consensus is a de-serialized consensus command.
type Consensus struct {
	ErrorCode uint8
	Payload   []byte
}

// ToBytes serializes the Consensus and returns the resulting byte slice.
func (c *Consensus) ToBytes() []byte {
	consensusLength := uint32(consensusBaseLength + len(c.Payload))
	out := make([]byte, cmdOverhead+consensusBaseLength, cmdOverhead+consensusLength)
	out[0] = byte(consensus) // out[1] is reserved
	binary.BigEndian.PutUint32(out[2:6], consensusLength)
	out[6] = c.ErrorCode
	out = append(out, c.Payload...)
	return out
}

func consensusFromBytes(b []byte) (Command, error) {
	if len(b) < consensusBaseLength {
		return nil, errInvalidCommand
	}

	r := new(Consensus)
	r.ErrorCode = b[0]
	if payloadLength := len(b) - consensusBaseLength; payloadLength > 0 {
		r.Payload = make([]byte, 0, payloadLength)
		r.Payload = append(r.Payload, b[consensusBaseLength:]...)
	}
	return r, nil
}

// PostDescriptor is a de-serialized post_descriptor command.
type PostDescriptor struct {
	Epoch   uint64
	Payload []byte
}

// ToBytes serializes the PostDescriptor and returns the resulting byte slice.
func (c *PostDescriptor) ToBytes() []byte {
	out := make([]byte, cmdOverhead+postDescriptorLength, cmdOverhead+postDescriptorLength+len(c.Payload))
	out[0] = byte(postDescriptor)
	binary.BigEndian.PutUint32(out[2:6], postDescriptorLength+uint32(len(c.Payload)))
	binary.BigEndian.PutUint64(out[6:14], c.Epoch)
	out = append(out, c.Payload...)
	return out
}

func postDescriptorFromBytes(b []byte) (Command, error) {
	if len(b) < postDescriptorLength {
		return nil, errInvalidCommand
	}

	r := new(PostDescriptor)
	r.Epoch = binary.BigEndian.Uint64(b[0:8])
	r.Payload = make([]byte, 0, len(b)-postDescriptorLength)
	r.Payload = append(r.Payload, b[postDescriptorLength:]...)
	return r, nil
}

// PostDescriptorStatus is a de-serialized post_descriptor_status command.
type PostDescriptorStatus struct {
	ErrorCode uint8
}

func postDescriptorStatusFromBytes(b []byte) (Command, error) {
	if len(b) != postDescriptorStatusLength {
		return nil, errInvalidCommand
	}

	r := new(PostDescriptorStatus)
	r.ErrorCode = b[0]
	return r, nil
}

// ToBytes serializes the PostDescriptorStatus and returns the resulting byte
// slice.
func (c *PostDescriptorStatus) ToBytes() []byte {
	out := make([]byte, cmdOverhead+postDescriptorStatusLength)
	out[0] = byte(postDescriptorStatus)
	binary.BigEndian.PutUint32(out[2:6], postDescriptorStatusLength)
	out[6] = c.ErrorCode
	return out
}

// Vote is a vote which is exchanged by Directory Authorities.
type Vote struct {
	Epoch     uint64
	PublicKey *eddsa.PublicKey
	Payload   []byte
}

func voteFromBytes(b []byte) (Command, error) {
	r := new(Vote)
	if len(b) < voteOverhead {
		return nil, errInvalidCommand
	}
	r.Epoch = binary.BigEndian.Uint64(b[0:8])
	r.PublicKey = new(eddsa.PublicKey)
	err := r.PublicKey.FromBytes(b[8:40])
	if err != nil {
		return nil, err
	}
	r.Payload = make([]byte, 0, len(b)-voteOverhead)
	r.Payload = append(r.Payload, b[voteOverhead:]...)
	return r, nil
}

func (c *Vote) ToBytes() []byte {
	out := make([]byte, cmdOverhead+8, cmdOverhead+voteOverhead+len(c.Payload))
	out[0] = byte(vote)
	binary.BigEndian.PutUint32(out[2:6], uint32(voteOverhead+len(c.Payload)))
	binary.BigEndian.PutUint64(out[6:14], c.Epoch)
	out = append(out, c.PublicKey.Bytes()...)
	out = append(out, c.Payload...)
	return out
}

// VoteStatus is a resonse status for a Vote command.
type VoteStatus struct {
	ErrorCode uint8
}

func (c *VoteStatus) ToBytes() []byte {
	out := make([]byte, cmdOverhead+voteStatusLength)
	out[0] = byte(voteStatus)
	binary.BigEndian.PutUint32(out[2:6], voteStatusLength)
	out[6] = c.ErrorCode
	return out
}

func voteStatusFromBytes(b []byte) (Command, error) {
	if len(b) != voteStatusLength {
		return nil, errInvalidCommand
	}

	r := new(VoteStatus)
	r.ErrorCode = b[0]
	return r, nil
}

// Disconnect is a de-serialized disconnect command.
type Disconnect struct{}

// ToBytes serializes the Disconnect and returns the resulting slice.
func (c *Disconnect) ToBytes() []byte {
	out := make([]byte, cmdOverhead)
	out[0] = byte(disconnect)
	return out
}

// SendPacket is a de-serialized send_packet command.
type SendPacket struct {
	SphinxPacket []byte
}

// ToBytes serializes the SendPacket and returns the resulting slice.
func (c *SendPacket) ToBytes() []byte {
	out := make([]byte, cmdOverhead, cmdOverhead+len(c.SphinxPacket))
	out[0] = byte(sendPacket)
	binary.BigEndian.PutUint32(out[2:6], uint32(len(c.SphinxPacket)))
	out = append(out, c.SphinxPacket...)
	return out
}

func sendPacketFromBytes(b []byte) (Command, error) {
	r := new(SendPacket)
	r.SphinxPacket = make([]byte, 0, len(b))
	r.SphinxPacket = append(r.SphinxPacket, b...)
	return r, nil
}

// RetrieveMessage is a de-serialized retreive_message command.
type RetrieveMessage struct {
	Sequence uint32
}

// ToBytes serializes the RetrieveMessage and returns the resulting slice.
func (c *RetrieveMessage) ToBytes() []byte {
	out := make([]byte, cmdOverhead+retreiveMessageLength)
	out[0] = byte(retreiveMessage)
	binary.BigEndian.PutUint32(out[2:6], retreiveMessageLength)
	binary.BigEndian.PutUint32(out[6:10], c.Sequence)
	return out
}

func retreiveMessageFromBytes(b []byte) (Command, error) {
	if len(b) != retreiveMessageLength {
		return nil, errInvalidCommand
	}

	r := new(RetrieveMessage)
	r.Sequence = binary.BigEndian.Uint32(b[0:4])
	return r, nil
}

// MessageACK is a de-serialized message command containing an ACK.
type MessageACK struct {
	QueueSizeHint uint8
	Sequence      uint32
	ID            [sphinxConstants.SURBIDLength]byte
	Payload       []byte
}

// ToBytes serializes the MessageACK and returns the resulting slice.
func (c *MessageACK) ToBytes() []byte {
	if len(c.Payload) != sphinx.PayloadTagLength+constants.ForwardPayloadLength {
		panic("wire: invalid MessageACK payload when serializing")
	}

	out := make([]byte, cmdOverhead+messageACKLength, cmdOverhead+messageACKLength+sphinx.PayloadTagLength+constants.ForwardPayloadLength)

	out[0] = byte(message)
	binary.BigEndian.PutUint32(out[2:6], messageACKLength+uint32(len(c.Payload)))
	out[6] = byte(messageTypeACK)
	out[7] = c.QueueSizeHint
	binary.BigEndian.PutUint32(out[8:12], c.Sequence)
	copy(out[12:12+sphinxConstants.SURBIDLength], c.ID[:])
	out = append(out, c.Payload...)
	return out
}

// Message is a de-serialized message command containing a message.
type Message struct {
	QueueSizeHint uint8
	Sequence      uint32
	Payload       []byte
}

// ToBytes serializes the Message and returns the resulting slice.
func (c *Message) ToBytes() []byte {
	if len(c.Payload) != constants.UserForwardPayloadLength {
		panic("wire: invalid Message payload when serializing")
	}

	out := make([]byte, cmdOverhead+messageMsgLength+len(c.Payload))
	out[0] = byte(message)
	binary.BigEndian.PutUint32(out[2:6], messageMsgLength+uint32(len(c.Payload)))
	out[6] = byte(messageTypeMessage)
	out[7] = c.QueueSizeHint
	binary.BigEndian.PutUint32(out[8:12], c.Sequence)
	copy(out[12:], c.Payload)
	return out
}

// MessageEmpty is a de-serialized message command signifying a empty queue.
type MessageEmpty struct {
	Sequence uint32
}

// ToBytes serializes the MessageEmpty and returns the resulting slice.
func (c *MessageEmpty) ToBytes() []byte {
	out := make([]byte, cmdOverhead+messageEmptyLength)

	out[0] = byte(message)
	binary.BigEndian.PutUint32(out[2:6], messageEmptyLength)
	out[6] = byte(messageTypeEmpty)
	binary.BigEndian.PutUint32(out[8:12], c.Sequence)
	return out
}

func messageFromBytes(b []byte) (Command, error) {
	if len(b) < messageBaseLength {
		return nil, errInvalidCommand
	}

	// Parse the common components belonging to all 3 message types.
	t := messageType(b[0])
	hint := b[1]
	seq := binary.BigEndian.Uint32(b[2:6])
	b = b[messageBaseLength:]

	switch t {
	case messageTypeACK:
		if len(b) != sphinxConstants.SURBIDLength+sphinx.PayloadTagLength+constants.ForwardPayloadLength {
			return nil, errInvalidCommand
		}

		r := new(MessageACK)
		r.QueueSizeHint = hint
		r.Sequence = seq
		copy(r.ID[:], b[:sphinxConstants.SURBIDLength])
		b = b[sphinxConstants.SURBIDLength:]
		r.Payload = make([]byte, 0, len(b))
		r.Payload = append(r.Payload, b...)
		return r, nil
	case messageTypeMessage:
		if len(b) != messageMsgPaddingLength+constants.UserForwardPayloadLength {
			return nil, errInvalidCommand
		}

		padding := b[constants.UserForwardPayloadLength:]
		if !utils.CtIsZero(padding) {
			return nil, errInvalidCommand
		}
		b = b[:constants.UserForwardPayloadLength]

		r := new(Message)
		r.QueueSizeHint = hint
		r.Sequence = seq
		r.Payload = make([]byte, 0, len(b))
		r.Payload = append(r.Payload, b...)
		return r, nil
	case messageTypeEmpty:
		if len(b) != messageEmptyLength-messageBaseLength {
			return nil, errInvalidCommand
		}

		if !utils.CtIsZero(b) {
			return nil, errInvalidCommand
		}

		r := new(MessageEmpty)
		r.Sequence = seq
		return r, nil
	default:
		return nil, errInvalidCommand
	}
}

// FromBytes de-serializes the command in the buffer b, returning a Command or
// an error.
func FromBytes(b []byte) (Command, error) {
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
			return &NoOp{}, nil
		case disconnect:
			return &Disconnect{}, nil
		case sendPacket, postDescriptor:
			// Shouldn't happen, but the caller should reject this, not the
			// de-serialization.
		default:
			return nil, errInvalidCommand
		}
	}

	// Handle the commands that require actual parsing.
	b = b[:cmdLen]
	switch commandID(id) {
	case sendPacket:
		return sendPacketFromBytes(b)
	case retreiveMessage:
		return retreiveMessageFromBytes(b)
	case message:
		return messageFromBytes(b)
	case getConsensus:
		return getConsensusFromBytes(b)
	case consensus:
		return consensusFromBytes(b)
	case postDescriptor:
		return postDescriptorFromBytes(b)
	case postDescriptorStatus:
		return postDescriptorStatusFromBytes(b)
	case getVote:
		return getVoteFromBytes(b)
	case vote:
		return voteFromBytes(b)
	case voteStatus:
		return voteStatusFromBytes(b)
	default:
		return nil, errInvalidCommand
	}
}

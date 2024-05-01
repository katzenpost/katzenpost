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
	"github.com/katzenpost/hpqc/sign"
	"github.com/katzenpost/katzenpost/core/cert"
	"github.com/katzenpost/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/katzenpost/katzenpost/core/utils"
)

const (
	cmdOverhead = 1 + 1 + 4

	retreiveMessageLength = 4
	messageBaseLength     = 1 + 1 + 4

	getConsensusLength  = 8
	consensusBaseLength = 1

	postDescriptorStatusLength = 1
	postDescriptorLength       = 8

	certStatusLength   = 1
	revealStatusLength = 1
	sigStatusLength    = 1
	voteStatusLength   = 1

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
	reveal               commandID = 25
	revealStatus         commandID = 26
	sig                  commandID = 27
	sigStatus            commandID = 28
	certificate          commandID = 29
	certStatus           commandID = 30

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

	// VoteNotAuthorized signifies that the voting entity's key is not authorized.
	VoteNotAuthorized = 3

	// VoteNotSigned signifies that the vote payload failed signature verification.
	VoteNotSigned = 4

	// VoteMalformed signifies that the vote payload was invalid.
	VoteMalformed = 5

	// VoteAlreadyReceived signifies that the vote from that peer was already received.
	VoteAlreadyReceived = 6

	// VoteNotFound signifies that the vote was not found.
	VoteNotFound = 7

	// RevealOk signifies that the reveal was accepted by the peer.
	RevealOk = 8

	// RevealTooEarly signifies that the peer is breaking protocol.
	RevealTooEarly = 9

	// RevealNotAuthorized signifies that the revealing entity's key is not authorized.
	RevealNotAuthorized = 10

	// RevealNotSigned signifies that the reveal payload failed signature verification.
	RevealNotSigned = 11

	// RevealAlreadyReceived signifies that the reveal from that peer was already received.
	RevealAlreadyReceived = 12

	// RevealTooLate signifies that the reveal from that peer arrived too late.
	RevealTooLate = 13

	// CertOk signifies that the certificate was accepted by the peer.
	CertOk = 14

	// CertTooEarly signifies that the peer is breaking protocol.
	CertTooEarly = 15

	// CertNotAuthorized signifies that the certifying entity's key is not
	CertNotAuthorized = 16

	// CertNotSigned signifies that the certficiate payload failed signature verification.
	CertNotSigned = 17

	// CertAlreadyReceived signifies that the certificate from that peer was already received.
	CertAlreadyReceived = 18

	// CertTooLate signifies that the certificate from that peer arrived too late.
	CertTooLate = 19

	// SigOK signifies that the signature was accepted by the peer.
	SigOk = 20

	// SigNotAuthorized signifies that the entity's key is not authorized.
	SigNotAuthorized = 21

	// SigNotSigned signifies that the signature command failed signature verification.
	SigNotSigned = 22

	// SigTooEarly signifies that the peer is breaking protocol.
	SigTooEarly = 23

	// SigTooLate signifies that the signature from that peer arrived too late.
	SigTooLate = 24

	// SigAlreadyReceived signifies that the signature from that peer was already received.
	SigAlreadyReceived = 25

	// SigInvalid signifies that the signature failed to deserialiez.
	SigInvalid = 26
)

var (
	errInvalidCommand = errors.New("wire: invalid wire protocol command")

	voteOverhead   = 8 + cert.Scheme.PublicKeySize()
	revealOverhead = 8 + cert.Scheme.PublicKeySize()
	certOverhead   = 8 + cert.Scheme.PublicKeySize()
	sigOverhead    = 8 + cert.Scheme.PublicKeySize()
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
	geo *geo.Geometry
}

// NewPKICommands returns a Commands without a given sphinx geometry.
func NewPKICommands() *Commands {
	return &Commands{
		geo: nil,
	}
}

// NewCommands returns a Commands given a sphinx geometry.
func NewCommands(geo *geo.Geometry) *Commands {
	return &Commands{
		geo: geo,
	}
}

func (c *Commands) messageMsgLength() int {
	return messageBaseLength + c.messageMsgPaddingLength()
}

func messageACKLength() int {
	return messageBaseLength + constants.SURBIDLength
}

func (c *Commands) messageEmptyLength() int {
	return messageACKLength() + c.geo.PayloadTagLength + c.geo.ForwardPayloadLength
}

func (c *Commands) messageMsgPaddingLength() int {
	return constants.SURBIDLength + c.geo.SphinxPlaintextHeaderLength + c.geo.SURBLength + c.geo.PayloadTagLength
}

func (c *Commands) maxMessageLenServerToClient() int {
	return cmdOverhead + c.messageMsgLength() + c.geo.UserForwardPayloadLength
}

func (c *Commands) maxMessageLenClientToServer() int {
	return cmdOverhead + c.geo.PacketLength
}

func (c *Commands) maxMessageLen(cmd Command) int {
	switch cmd.(type) {
	case *NoOp, *SendPacket, *Disconnect, *RetrieveMessage, *GetConsensus:
		// These are client to server commands
		return c.maxMessageLenClientToServer()
	case *Message, *MessageACK, *MessageEmpty:
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

// GetConsensus is a de-serialized get_consensus command.
type GetConsensus struct {
	Epoch uint64
	Cmds  *Commands
}

// ToBytes serializes the GetConsensus and returns the resulting byte slice.
func (c *GetConsensus) ToBytes() []byte {
	out := make([]byte, cmdOverhead+getConsensusLength)
	out[0] = byte(getConsensus)
	binary.BigEndian.PutUint32(out[2:6], getConsensusLength)
	binary.BigEndian.PutUint64(out[6:14], c.Epoch)
	return padToMaxCommandSize(out, c.Cmds.maxMessageLen(c))
}

func getConsensusFromBytes(b []byte, cmds *Commands) (Command, error) {
	if len(b) != getConsensusLength {
		return nil, errInvalidCommand
	}

	r := new(GetConsensus)
	r.Epoch = binary.BigEndian.Uint64(b[0:8])
	r.Cmds = cmds
	return r, nil
}

// GetVote is a de-serialized get_vote command.
type GetVote struct {
	Epoch     uint64
	PublicKey sign.PublicKey
}

// ToBytes serializes the GetVote and returns the resulting slice.
func (v *GetVote) ToBytes() []byte {
	out := make([]byte, cmdOverhead+8, cmdOverhead+voteOverhead)
	out[0] = byte(getVote)
	binary.BigEndian.PutUint32(out[2:6], uint32(voteOverhead))
	binary.BigEndian.PutUint64(out[6:14], v.Epoch)
	blob, err := v.PublicKey.MarshalBinary()
	if err != nil {
		panic(err)
	}
	out = append(out, blob...)
	return out
}

func getVoteFromBytes(b []byte) (Command, error) {
	if len(b) != voteOverhead {
		return nil, errInvalidCommand
	}
	r := new(GetVote)
	r.Epoch = binary.BigEndian.Uint64(b[0:8])
	var err error
	r.PublicKey, err = cert.Scheme.UnmarshalBinaryPublicKey(b[8 : cert.Scheme.PublicKeySize()+8])
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

// Reveal is a de-serialized reveal command exchanged by authorities.
type Reveal struct {
	Epoch     uint64
	PublicKey sign.PublicKey
	Payload   []byte
}

// ToBytes serializes the Reveal and returns the resulting byte slice.
func (r *Reveal) ToBytes() []byte {
	out := make([]byte, cmdOverhead+revealOverhead)
	out[0] = byte(reveal)
	// out[1] reserved
	binary.BigEndian.PutUint32(out[2:6], uint32(revealOverhead+len(r.Payload)))
	binary.BigEndian.PutUint64(out[6:14], r.Epoch)
	blob, err := r.PublicKey.MarshalBinary()
	if err != nil {
		panic(err)
	}
	copy(out[14:14+cert.Scheme.PublicKeySize()], blob)
	out = append(out, r.Payload...)
	return out
}

func revealFromBytes(b []byte) (Command, error) {
	if len(b) < revealOverhead {
		return nil, errors.New(" wtf: errInvalidCommand")
	}

	r := new(Reveal)
	r.Epoch = binary.BigEndian.Uint64(b[0:8])
	var err error
	r.PublicKey, err = cert.Scheme.UnmarshalBinaryPublicKey(b[8 : 8+cert.Scheme.PublicKeySize()])
	if err != nil {
		return nil, err
	}
	r.Payload = make([]byte, 0, len(b)-revealOverhead)
	r.Payload = append(r.Payload, b[revealOverhead:]...)
	return r, nil
}

// RevealStatus is a de-serialized revealStatus command.
type RevealStatus struct {
	ErrorCode uint8
}

func revealStatusFromBytes(b []byte) (Command, error) {
	if len(b) != revealStatusLength {
		return nil, errors.New(" wtf: errInvalidCommand")
	}

	r := new(RevealStatus)
	r.ErrorCode = b[0]
	return r, nil
}

// ToBytes serializes the RevealStatus and returns the resulting byte slice.
func (r *RevealStatus) ToBytes() []byte {
	out := make([]byte, cmdOverhead+revealStatusLength)
	out[0] = byte(revealStatus)
	binary.BigEndian.PutUint32(out[2:6], revealStatusLength)
	out[6] = r.ErrorCode
	return out
}

// Vote is a vote which is exchanged by Directory Authorities.
type Vote struct {
	Epoch     uint64
	PublicKey sign.PublicKey
	Payload   []byte
}

func voteFromBytes(b []byte) (Command, error) {
	r := new(Vote)
	if len(b) < voteOverhead {
		return nil, errInvalidCommand
	}
	r.Epoch = binary.BigEndian.Uint64(b[0:8])
	var err error
	r.PublicKey, err = cert.Scheme.UnmarshalBinaryPublicKey(b[8 : 8+cert.Scheme.PublicKeySize()])
	if err != nil {
		return nil, err
	}
	r.Payload = make([]byte, 0, len(b)-voteOverhead)
	r.Payload = append(r.Payload, b[voteOverhead:]...)
	return r, nil
}

// ToBytes serializes the Vote and returns the resulting slice.
func (c *Vote) ToBytes() []byte {
	out := make([]byte, cmdOverhead+8, cmdOverhead+voteOverhead+len(c.Payload))
	out[0] = byte(vote)
	binary.BigEndian.PutUint32(out[2:6], uint32(voteOverhead+len(c.Payload)))
	binary.BigEndian.PutUint64(out[6:14], c.Epoch)
	blob, err := c.PublicKey.MarshalBinary()
	if err != nil {
		panic(err)
	}
	out = append(out, blob...)
	out = append(out, c.Payload...)
	return out
}

// VoteStatus is a resonse status for a Vote command.
type VoteStatus struct {
	ErrorCode uint8
}

// ToBytes serializes the VoteStatus and returns the resulting slice.
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

// Cert is a potential consensus which is exchanged by Directory Authorities.
type Cert struct {
	Epoch     uint64
	PublicKey sign.PublicKey
	Payload   []byte
}

func certFromBytes(b []byte) (Command, error) {
	r := new(Cert)
	if len(b) < certOverhead {
		return nil, errInvalidCommand
	}
	r.Epoch = binary.BigEndian.Uint64(b[0:8])
	var err error
	r.PublicKey, err = cert.Scheme.UnmarshalBinaryPublicKey(b[8 : 8+cert.Scheme.PublicKeySize()])
	if err != nil {
		return nil, err
	}
	r.Payload = make([]byte, 0, len(b)-certOverhead)
	r.Payload = append(r.Payload, b[certOverhead:]...)
	return r, nil
}

// ToBytes serializes the Cert and returns the resulting slice.
func (c *Cert) ToBytes() []byte {
	out := make([]byte, cmdOverhead+8, cmdOverhead+certOverhead+len(c.Payload))
	out[0] = byte(certificate)
	binary.BigEndian.PutUint32(out[2:6], uint32(certOverhead+len(c.Payload)))
	binary.BigEndian.PutUint64(out[6:14], c.Epoch)
	blob, err := c.PublicKey.MarshalBinary()
	if err != nil {
		panic(err)
	}
	out = append(out, blob...)
	out = append(out, c.Payload...)
	return out
}

// CertStatus is a resonse status for a Cert command.
type CertStatus struct {
	ErrorCode uint8
}

// ToBytes serializes the CertStatus and returns the resulting slice.
func (c *CertStatus) ToBytes() []byte {
	out := make([]byte, cmdOverhead+certStatusLength)
	out[0] = byte(certStatus)
	binary.BigEndian.PutUint32(out[2:6], certStatusLength)
	out[6] = c.ErrorCode
	return out
}

func certStatusFromBytes(b []byte) (Command, error) {
	if len(b) != certStatusLength {
		return nil, errInvalidCommand
	}

	r := new(CertStatus)
	r.ErrorCode = b[0]
	return r, nil
}

// Sig is a signature which is exchanged by Directory Authorities.
type Sig struct {
	Epoch     uint64
	PublicKey sign.PublicKey
	Payload   []byte
}

func sigFromBytes(b []byte) (Command, error) {
	r := new(Sig)
	if len(b) < sigOverhead {
		return nil, errInvalidCommand
	}
	r.Epoch = binary.BigEndian.Uint64(b[0:8])
	var err error
	r.PublicKey, err = cert.Scheme.UnmarshalBinaryPublicKey(b[8 : 8+cert.Scheme.PublicKeySize()])
	if err != nil {
		return nil, err
	}
	r.Payload = make([]byte, 0, len(b)-sigOverhead)
	r.Payload = append(r.Payload, b[sigOverhead:]...)
	return r, nil
}

// ToBytes serializes the Sig and returns the resulting slice.
func (c *Sig) ToBytes() []byte {
	out := make([]byte, cmdOverhead+8, cmdOverhead+sigOverhead+len(c.Payload))
	out[0] = byte(sig)
	binary.BigEndian.PutUint32(out[2:6], uint32(sigOverhead+len(c.Payload)))
	binary.BigEndian.PutUint64(out[6:14], c.Epoch)
	blob, err := c.PublicKey.MarshalBinary()
	if err != nil {
		panic(err)
	}
	out = append(out, blob...)
	out = append(out, c.Payload...)
	return out
}

// SigStatus is a resonse status for a Sig command.
type SigStatus struct {
	ErrorCode uint8
}

// ToBytes serializes the Status and returns the resulting slice.
func (c *SigStatus) ToBytes() []byte {
	out := make([]byte, cmdOverhead+sigStatusLength)
	out[0] = byte(sigStatus)
	binary.BigEndian.PutUint32(out[2:6], sigStatusLength)
	out[6] = c.ErrorCode
	return out
}

func sigStatusFromBytes(b []byte) (Command, error) {
	if len(b) != sigStatusLength {
		return nil, errInvalidCommand
	}

	r := new(SigStatus)
	r.ErrorCode = b[0]
	return r, nil
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

// SendPacket is a de-serialized send_packet command.
type SendPacket struct {
	SphinxPacket []byte
	Cmds         *Commands
}

// ToBytes serializes the SendPacket and returns the resulting slice.
func (c *SendPacket) ToBytes() []byte {
	out := make([]byte, cmdOverhead, cmdOverhead+len(c.SphinxPacket))
	out[0] = byte(sendPacket)
	binary.BigEndian.PutUint32(out[2:6], uint32(len(c.SphinxPacket)))
	out = append(out, c.SphinxPacket...)
	return padToMaxCommandSize(out, c.Cmds.maxMessageLen(c))
}

func sendPacketFromBytes(b []byte, cmds *Commands) (Command, error) {
	r := new(SendPacket)
	r.SphinxPacket = make([]byte, 0, len(b))
	r.SphinxPacket = append(r.SphinxPacket, b...)
	r.Cmds = cmds
	return r, nil
}

// RetrieveMessage is a de-serialized retrieve_message command.
type RetrieveMessage struct {
	Sequence uint32
	Cmds     *Commands
}

// ToBytes serializes the RetrieveMessage and returns the resulting slice.
func (c *RetrieveMessage) ToBytes() []byte {
	out := make([]byte, cmdOverhead+retreiveMessageLength)
	out[0] = byte(retreiveMessage)
	binary.BigEndian.PutUint32(out[2:6], retreiveMessageLength)
	binary.BigEndian.PutUint32(out[6:10], c.Sequence)
	return padToMaxCommandSize(out, c.Cmds.maxMessageLen(c))
}

func retreiveMessageFromBytes(b []byte, cmds *Commands) (Command, error) {
	if len(b) != retreiveMessageLength {
		return nil, errInvalidCommand
	}

	r := new(RetrieveMessage)
	r.Sequence = binary.BigEndian.Uint32(b[0:4])
	r.Cmds = cmds
	return r, nil
}

// MessageACK is a de-serialized message command containing an ACK.
type MessageACK struct {
	Geo  *geo.Geometry
	Cmds *Commands

	QueueSizeHint uint8
	Sequence      uint32
	ID            [constants.SURBIDLength]byte
	Payload       []byte
}

// ToBytes serializes the MessageACK and returns the resulting slice.
func (c *MessageACK) ToBytes() []byte {
	if len(c.Payload) != c.Geo.PayloadTagLength+c.Geo.ForwardPayloadLength {
		panic("wire: invalid MessageACK payload when serializing")
	}

	out := make([]byte, cmdOverhead+messageACKLength(), cmdOverhead+messageACKLength()+c.Geo.PayloadTagLength+c.Geo.ForwardPayloadLength)

	out[0] = byte(message)
	binary.BigEndian.PutUint32(out[2:6], uint32(messageACKLength()+len(c.Payload)))
	out[6] = byte(messageTypeACK)
	out[7] = c.QueueSizeHint
	binary.BigEndian.PutUint32(out[8:12], c.Sequence)
	copy(out[12:12+constants.SURBIDLength], c.ID[:])
	out = append(out, c.Payload...)
	return padToMaxCommandSize(out, c.Cmds.maxMessageLen(c))
}

// Message is a de-serialized message command containing a message.
type Message struct {
	Geo  *geo.Geometry
	Cmds *Commands

	QueueSizeHint uint8
	Sequence      uint32
	Payload       []byte
}

// ToBytes serializes the Message and returns the resulting slice.
func (c *Message) ToBytes() []byte {
	if len(c.Payload) != c.Geo.UserForwardPayloadLength {
		panic("wire: invalid Message payload when serializing")
	}

	out := make([]byte, cmdOverhead+c.Cmds.messageMsgLength()+len(c.Payload))
	out[0] = byte(message)
	binary.BigEndian.PutUint32(out[2:6], uint32(c.Cmds.messageMsgLength()+len(c.Payload)))
	out[6] = byte(messageTypeMessage)
	out[7] = c.QueueSizeHint
	binary.BigEndian.PutUint32(out[8:12], c.Sequence)
	copy(out[12:], c.Payload)
	return padToMaxCommandSize(out, c.Cmds.maxMessageLen(c))
}

// MessageEmpty is a de-serialized message command signifying a empty queue.
type MessageEmpty struct {
	Cmds *Commands

	Sequence uint32
}

// ToBytes serializes the MessageEmpty and returns the resulting slice.
func (c *MessageEmpty) ToBytes() []byte {
	out := make([]byte, cmdOverhead+c.Cmds.messageEmptyLength())

	out[0] = byte(message)
	binary.BigEndian.PutUint32(out[2:6], uint32(c.Cmds.messageEmptyLength()))
	out[6] = byte(messageTypeEmpty)
	binary.BigEndian.PutUint32(out[8:12], c.Sequence)
	return padToMaxCommandSize(out, c.Cmds.maxMessageLen(c))
}

func (c *Commands) messageFromBytes(b []byte, cmds *Commands) (Command, error) {
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
		if len(b) != constants.SURBIDLength+c.geo.PayloadTagLength+c.geo.ForwardPayloadLength {
			return nil, errInvalidCommand
		}

		r := new(MessageACK)
		r.QueueSizeHint = hint
		r.Sequence = seq
		copy(r.ID[:], b[:constants.SURBIDLength])
		b = b[constants.SURBIDLength:]
		r.Payload = make([]byte, 0, len(b))
		r.Payload = append(r.Payload, b...)
		r.Cmds = cmds
		return r, nil
	case messageTypeMessage:
		if len(b) != c.messageMsgPaddingLength()+c.geo.UserForwardPayloadLength {
			return nil, errInvalidCommand
		}

		padding := b[c.geo.UserForwardPayloadLength:]
		if !utils.CtIsZero(padding) {
			return nil, errInvalidCommand
		}
		b = b[:c.geo.UserForwardPayloadLength]

		r := new(Message)
		r.QueueSizeHint = hint
		r.Sequence = seq
		r.Payload = make([]byte, 0, len(b))
		r.Payload = append(r.Payload, b...)
		r.Cmds = cmds
		return r, nil
	case messageTypeEmpty:
		if len(b) != c.messageEmptyLength()-messageBaseLength {
			return nil, errInvalidCommand
		}

		if !utils.CtIsZero(b) {
			return nil, errInvalidCommand
		}

		r := new(MessageEmpty)
		r.Sequence = seq
		r.Cmds = cmds
		return r, nil
	default:
		return nil, errInvalidCommand
	}
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
		return getVoteFromBytes(b)
	case vote:
		return voteFromBytes(b)
	case voteStatus:
		return voteStatusFromBytes(b)
	case certificate:
		return certFromBytes(b)
	case certStatus:
		return certStatusFromBytes(b)
	case reveal:
		return revealFromBytes(b)
	case revealStatus:
		return revealStatusFromBytes(b)
	case sig:
		return sigFromBytes(b)
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

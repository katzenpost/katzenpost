// SPDX-FileCopyrightText: Copyright (C) 2017  David Anthony Stainton, Yawning Angel
// SPDX-License-Identifier: AGPL-3.0-only

package commands

import (
	"encoding/binary"

	"github.com/katzenpost/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
)

func messageLength() int {
	return messageBaseLength + constants.SURBIDLength
}

// SendPacket is a de-serialized send_packet command.
type SendPacket struct {
	SphinxPacket []byte
	Cmds         *Commands
}

func (c *SendPacket) String() string { return "SendPacket" }

// ToBytes serializes the SendPacket and returns the resulting slice.
func (c *SendPacket) ToBytes() []byte {
	out := make([]byte, cmdOverhead, cmdOverhead+len(c.SphinxPacket))
	out[0] = byte(sendPacket)
	binary.BigEndian.PutUint32(out[2:6], uint32(len(c.SphinxPacket)))
	out = append(out, c.SphinxPacket...)
	return c.Cmds.padToMaxCommandSize(out, true)
}

func (c *SendPacket) Length() int {
	return cmdOverhead + c.Cmds.geo.PacketLength
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

func (c *RetrieveMessage) String() string { return "RetrieveMessage" }

// ToBytes serializes the RetrieveMessage and returns the resulting slice.
func (c *RetrieveMessage) ToBytes() []byte {
	out := make([]byte, cmdOverhead+retreiveMessageLength)
	out[0] = byte(retreiveMessage)
	binary.BigEndian.PutUint32(out[2:6], retreiveMessageLength)
	binary.BigEndian.PutUint32(out[6:10], c.Sequence)
	return c.Cmds.padToMaxCommandSize(out, true)
}

func (c *RetrieveMessage) Length() int {
	return cmdOverhead + 4
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

// MessageDelivered is the client→gateway acknowledgement of a Message
// that was pushed unsolicited by the gateway. The Sequence echoes the
// value the gateway assigned to the pushed command, identifying which
// spool entry the gateway may now advance past.
type MessageDelivered struct {
	Sequence uint32
	Cmds     *Commands
}

func (c *MessageDelivered) String() string { return "MessageDelivered" }

// ToBytes serializes the MessageDelivered and returns the resulting slice.
func (c *MessageDelivered) ToBytes() []byte {
	out := make([]byte, cmdOverhead+messageDeliveredLength)
	out[0] = byte(messageDelivered)
	binary.BigEndian.PutUint32(out[2:6], messageDeliveredLength)
	binary.BigEndian.PutUint32(out[6:10], c.Sequence)
	return c.Cmds.padToMaxCommandSize(out, true)
}

func (c *MessageDelivered) Length() int {
	return cmdOverhead + messageDeliveredLength
}

func messageDeliveredFromBytes(b []byte, cmds *Commands) (Command, error) {
	if len(b) != messageDeliveredLength {
		return nil, errInvalidCommand
	}

	r := new(MessageDelivered)
	r.Sequence = binary.BigEndian.Uint32(b[0:4])
	r.Cmds = cmds
	return r, nil
}

// Message is a de-serialized message command carrying a SURB reply
// that the gateway pushed unsolicited to a connected client. The
// Sequence correlates the matching MessageDelivered the client returns.
type Message struct {
	Geo  *geo.Geometry
	Cmds *Commands

	Sequence uint32
	SURBID   [constants.SURBIDLength]byte
	Payload  []byte
}

func (c *Message) String() string { return "Message" }

// ToBytes serializes the Message and returns the resulting slice.
func (c *Message) ToBytes() []byte {
	if len(c.Payload) != c.Geo.PayloadTagLength+c.Geo.ForwardPayloadLength {
		panic("wire: invalid Message payload when serializing")
	}

	out := make([]byte, cmdOverhead+messageLength(), cmdOverhead+messageLength()+c.Geo.PayloadTagLength+c.Geo.ForwardPayloadLength)

	out[0] = byte(message)
	binary.BigEndian.PutUint32(out[2:6], uint32(messageLength()+len(c.Payload)))
	out[6] = byte(messageTypeMessage)
	binary.BigEndian.PutUint32(out[7:11], c.Sequence)
	copy(out[11:11+constants.SURBIDLength], c.SURBID[:])
	out = append(out, c.Payload...)
	return c.Cmds.padToMaxCommandSize(out, false)
}

func (c *Message) Length() int {
	return cmdOverhead + 1 + 4 + constants.SURBIDLength + c.Geo.PacketLength
}

func (c *Commands) messageFromBytes(b []byte, cmds *Commands) (Command, error) {
	if len(b) < messageBaseLength {
		return nil, errInvalidCommand
	}

	t := messageType(b[0])
	seq := binary.BigEndian.Uint32(b[1:5])
	b = b[messageBaseLength:]

	switch t {
	case messageTypeMessage:
		if len(b) != constants.SURBIDLength+c.geo.PayloadTagLength+c.geo.ForwardPayloadLength {
			return nil, errInvalidCommand
		}

		r := new(Message)
		r.Sequence = seq
		copy(r.SURBID[:], b[:constants.SURBIDLength])
		b = b[constants.SURBIDLength:]
		r.Payload = make([]byte, 0, len(b))
		r.Payload = append(r.Payload, b...)
		r.Cmds = cmds
		return r, nil
	default:
		return nil, errInvalidCommand
	}
}

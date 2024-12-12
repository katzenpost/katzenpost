// SPDX-FileCopyrightText: Copyright (C) 2017  David Anthony Stainton, Yawning Angel
// SPDX-License-Identifier: AGPL-3.0-only

package commands

import (
	"encoding/binary"

	"github.com/katzenpost/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/katzenpost/katzenpost/core/utils"
)

func (c *Commands) messageMsgPaddingLength() int {
	return constants.SURBIDLength + c.geo.SphinxPlaintextHeaderLength + c.geo.SURBLength + c.geo.PayloadTagLength
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
	return c.Cmds.padToMaxCommandSize(out, false)
}

func (c *MessageACK) Length() int {
	return cmdOverhead + 1 + 4 + constants.SURBIDLength + c.Geo.PacketLength
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
	return c.Cmds.padToMaxCommandSize(out, false)
}

func (c *Message) Length() int {
	return cmdOverhead + 1 + 4 + c.Geo.PacketLength
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
	return c.Cmds.padToMaxCommandSize(out, false)
}

func (c *MessageEmpty) Length() int {
	return cmdOverhead + 4 + c.Cmds.geo.PacketLength
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

// SPDX-FileCopyrightText: Copyright (C) 2024  David Anthony Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package commands

import (
	"encoding/binary"

	"github.com/katzenpost/katzenpost/core/sphinx/geo"
)

// NIKE scheme CTIDH1024-X25519 has 160 byte public keys
const HybridKeySize = 160

type ReplicaRead struct {
	Cmds *Commands

	ID *[32]byte
}

func (c *ReplicaRead) ToBytes() []byte {
	out := make([]byte, cmdOverhead, cmdOverhead+32)
	out[0] = byte(replicaRead)
	binary.BigEndian.PutUint32(out[2:6], uint32(c.Length()-cmdOverhead))
	out = append(out, c.ID[:]...)
	return c.Cmds.padToMaxCommandSize(out, true)
}

func (c *ReplicaRead) Length() int {
	return cmdOverhead + 32
}

func replicaReadFromBytes(b []byte, cmds *Commands) (Command, error) {
	c := new(ReplicaRead)
	c.Cmds = cmds
	c.ID = &[32]byte{}
	copy(c.ID[:], b[:32])
	return c, nil
}

type ReplicaReadReply struct {
	Cmds *Commands
	Geo  *geo.Geometry

	ErrorCode uint8
	ID        *[32]byte
	Signature *[32]byte
	Payload   []byte
}

func (c *ReplicaReadReply) ToBytes() []byte {
	const (
		errorCodeLen = 1
		idLen        = 32
		sigLen       = 32
	)
	out := make([]byte, cmdOverhead, cmdOverhead+errorCodeLen+idLen+sigLen+len(c.Payload))
	out[0] = byte(replicaReadReply)
	binary.BigEndian.PutUint32(out[2:6], uint32(c.Length()-cmdOverhead))
	out = append(out, c.ErrorCode)
	out = append(out, c.ID[:]...)
	out = append(out, c.Signature[:]...)
	out = append(out, c.Payload...)

	return c.Cmds.padToMaxCommandSize(out, true)
}

func (c *ReplicaReadReply) Length() int {
	const (
		errorCodeLen  = 1
		idLen         = 32
		sigLen        = 32
		signatureSize = 32
	)
	// XXX replace c.Geo.PacketLength with the precise payload size
	return cmdOverhead + errorCodeLen + idLen + sigLen + signatureSize + c.Geo.PacketLength
}

func replicaReadReplyFromBytes(b []byte, cmds *Commands) (Command, error) {
	c := new(ReplicaReadReply)
	c.Cmds = cmds
	c.Geo = cmds.geo
	c.ID = &[32]byte{}
	c.ErrorCode = b[0]
	copy(c.ID[:], b[1:32+1])
	c.Signature = &[32]byte{}
	copy(c.Signature[:], b[1+32:1+32+32])
	c.Payload = make([]byte, len(b[1+32+32:]))
	copy(c.Payload, b[1+32+32:])
	return c, nil
}

type ReplicaWrite struct {
	Cmds *Commands

	ID        *[32]byte
	Signature *[32]byte
	Payload   []byte
}

func (c *ReplicaWrite) ToBytes() []byte {
	out := make([]byte, cmdOverhead, cmdOverhead+32+32+len(c.Payload))
	out[0] = byte(replicaWrite)
	binary.BigEndian.PutUint32(out[2:6], uint32(c.Length()-cmdOverhead))
	out = append(out, c.ID[:]...)
	out = append(out, c.Signature[:]...)
	out = append(out, c.Payload...)

	return c.Cmds.padToMaxCommandSize(out, true)
}

func (c *ReplicaWrite) Length() int {
	const (
		// XXX FIX ME: largest ideal command size goes here
		payloadSize   = 1000
		signatureSize = 32
	)
	return cmdOverhead + payloadSize + signatureSize
}

func replicaWriteFromBytes(b []byte, cmds *Commands) (Command, error) {
	c := new(ReplicaWrite)
	c.Cmds = cmds
	c.ID = &[32]byte{}
	copy(c.ID[:], b[:32])
	c.Signature = &[32]byte{}
	copy(c.Signature[:], b[32:32+32])
	c.Payload = make([]byte, len(b[32+32:]))
	copy(c.Payload, b[32+32:])
	return c, nil
}

type ReplicaWriteReply struct {
	Cmds *Commands

	ErrorCode uint8
}

func (c *ReplicaWriteReply) ToBytes() []byte {
	out := make([]byte, cmdOverhead+replicaMessageReplyLength)
	out[0] = byte(replicaWriteReply)
	binary.BigEndian.PutUint32(out[2:6], replicaWriteReplyLength)
	out[6] = c.ErrorCode
	return c.Cmds.padToMaxCommandSize(out, true)
}

func replicaWriteReplyFromBytes(b []byte, cmds *Commands) (Command, error) {
	if len(b) != postDescriptorStatusLength {
		return nil, errInvalidCommand
	}

	r := new(ReplicaWriteReply)
	r.Cmds = cmds
	r.ErrorCode = b[0]
	return r, nil
}

func (c *ReplicaWriteReply) Length() int {
	return 0
}

type ReplicaMessage struct {
	Cmds *Commands
	Geo  *geo.Geometry

	ReplicaID     uint8
	SenderEPubKey *[HybridKeySize]byte
	DEK           *[32]byte
	Ciphertext    []byte
}

func (c *ReplicaMessage) ToBytes() []byte {
	out := make([]byte, cmdOverhead, cmdOverhead+32+len(c.Ciphertext))
	out[0] = byte(replicaMessage)
	binary.BigEndian.PutUint32(out[2:6], uint32(c.Length()-cmdOverhead))

	out = append(out, c.ReplicaID)
	out = append(out, c.SenderEPubKey[:]...)
	out = append(out, c.DEK[:]...)
	out = append(out, c.Ciphertext...)

	return c.Cmds.padToMaxCommandSize(out, true)
}

func replicaMessageFromBytes(b []byte, cmds *Commands) (Command, error) {
	c := new(ReplicaMessage)
	c.Cmds = cmds

	c.ReplicaID = b[0]

	c.SenderEPubKey = &[160]byte{}
	copy(c.SenderEPubKey[:], b[1:HybridKeySize+1])

	c.DEK = &[32]byte{}
	copy(c.DEK[:], b[1+HybridKeySize:1+HybridKeySize+32])

	// c.Cmds.geo.PacketLength
	c.Ciphertext = make([]byte, len(b[1+HybridKeySize+32:]))
	copy(c.Ciphertext, b[1+HybridKeySize+32:])

	return c, nil
}

func (c *ReplicaMessage) Length() int {
	const (
		idLen         = 32
		sigLen        = 32
		signatureSize = 32
	)
	// XXX replace c.Geo.PacketLength with the precise payload size
	return cmdOverhead + idLen + sigLen + signatureSize + c.Geo.PacketLength
}

type ReplicaMessageReply struct {
	Cmds *Commands

	ErrorCode uint8
}

func (c *ReplicaMessageReply) ToBytes() []byte {
	out := make([]byte, cmdOverhead+replicaMessageReplyLength)
	out[0] = byte(postReplicaDescriptorStatus)
	binary.BigEndian.PutUint32(out[2:6], replicaMessageReplyLength)
	out[6] = c.ErrorCode
	return c.Cmds.padToMaxCommandSize(out, true)
}

func replicaMessageReplyFromBytes(b []byte) (Command, error) {
	if len(b) != postDescriptorStatusLength {
		return nil, errInvalidCommand
	}

	r := new(ReplicaMessageReply)
	r.ErrorCode = b[0]
	return r, nil
}

func (c *ReplicaMessageReply) Length() int {
	return 0
}

// SPDX-FileCopyrightText: Copyright (C) 2024  David Anthony Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package commands

import (
	"encoding/binary"

	"github.com/katzenpost/hpqc/nike"

	"github.com/katzenpost/katzenpost/core/sphinx/geo"
)

func HybridKeySize(scheme nike.Scheme) int {
	// NIKE scheme CTIDH1024-X25519 has 160 byte public keys
	return scheme.PublicKeySize()

}

// ReplicaRead isn't used directly on the wire protocol
// but is embedded inside the ReplicaMessage which of course
// are sent by the couriers to the replicas.
type ReplicaRead struct {
	Cmds *Commands

	BoxID *[32]byte
}

func (c *ReplicaRead) ToBytes() []byte {
	out := make([]byte, cmdOverhead, cmdOverhead+32)
	out[0] = byte(replicaRead)
	binary.BigEndian.PutUint32(out[2:6], uint32(c.Length()-cmdOverhead))
	return append(out, c.BoxID[:]...)
}

func (c *ReplicaRead) Length() int {
	return cmdOverhead + 32
}

func replicaReadFromBytes(b []byte, cmds *Commands) (Command, error) {
	c := new(ReplicaRead)
	c.Cmds = cmds
	c.BoxID = &[32]byte{}
	copy(c.BoxID[:], b[:32])
	return c, nil
}

// ReplicaReadReply isn't used directly on the wire protocol
// but is embedded inside the ReplicaMessageReply which of course
// are sent by the replicas to the couriers. Therefore the
// ReplicaReadReply command is never padded because it is always
// encapsulated by the ReplicaMessageReply which is padded.
type ReplicaReadReply struct {
	Cmds *Commands
	Geo  *geo.Geometry

	ErrorCode uint8
	BoxID     *[32]byte
	Signature *[32]byte
	Payload   []byte
}

func (c *ReplicaReadReply) ToBytes() []byte {
	const (
		errorCodeLen = 1
		idLen        = 32
		sigLen       = 32
	)
	length := errorCodeLen + idLen + sigLen + c.Geo.PacketLength
	out := make([]byte, cmdOverhead, cmdOverhead+errorCodeLen+idLen+sigLen+len(c.Payload))
	out[0] = byte(replicaReadReply)
	binary.BigEndian.PutUint32(out[2:6], uint32(length))
	out = append(out, c.ErrorCode)
	out = append(out, c.BoxID[:]...)
	out = append(out, c.Signature[:]...)
	payload := make([]byte, c.Geo.PacketLength)
	copy(payload, c.Payload)
	return append(out, payload...)
}

func (c *ReplicaReadReply) Length() int {
	const (
		errorCodeLen  = 1
		idLen         = 32
		sigLen        = 32
		signatureSize = 32
	)
	// XXX replace c.Geo.PacketLength with the precise payload size
	//return cmdOverhead + errorCodeLen + idLen + sigLen + signatureSize + c.Geo.PacketLength
	return 0
}

func replicaReadReplyFromBytes(b []byte, cmds *Commands) (Command, error) {
	c := new(ReplicaReadReply)
	c.Cmds = cmds
	c.Geo = cmds.geo
	c.BoxID = &[32]byte{}
	c.ErrorCode = b[0]
	copy(c.BoxID[:], b[1:32+1])
	c.Signature = &[32]byte{}
	copy(c.Signature[:], b[1+32:1+32+32])
	c.Payload = make([]byte, len(b[1+32+32:]))
	copy(c.Payload, b[1+32+32:])
	return c, nil
}

// ReplicaWrite has two distinct uses. Firstly, it is
// to be used directly on the wire for replication between replicas.
// Secondly, it can be embedded inside a ReplicaMessage which of course
// are sent from couriers to replicas.
type ReplicaWrite struct {
	Cmds *Commands

	BoxID     *[32]byte
	Signature *[32]byte
	Payload   []byte
}

func (c *ReplicaWrite) ToBytes() []byte {
	out := make([]byte, cmdOverhead, cmdOverhead+32+32+len(c.Payload))
	out[0] = byte(replicaWrite)
	binary.BigEndian.PutUint32(out[2:6], uint32(c.Length()-cmdOverhead))
	out = append(out, c.BoxID[:]...)
	out = append(out, c.Signature[:]...)
	out = append(out, c.Payload...)

	// optional traffic padding
	if c.Cmds == nil {
		return out
	}
	return c.Cmds.padToMaxCommandSize(out, true)
}

func (c *ReplicaWrite) Length() int {
	var (
		// XXX FIX ME: largest ideal command size goes here
		payloadSize   = c.Cmds.geo.PacketLength
		signatureSize = 32
	)
	return cmdOverhead + payloadSize + signatureSize
}

func replicaWriteFromBytes(b []byte, cmds *Commands) (Command, error) {
	c := new(ReplicaWrite)
	c.Cmds = cmds
	c.BoxID = &[32]byte{}
	copy(c.BoxID[:], b[:32])
	c.Signature = &[32]byte{}
	copy(c.Signature[:], b[32:32+32])
	c.Payload = make([]byte, len(b[32+32:]))
	copy(c.Payload, b[32+32:])
	return c, nil
}

// ReplicaWriteReply can facilitate replication between replicas as the
// reply to the ReplicaWrite command. Otherwise it is embedded in a
// ReplicaMessageReply and sent from replicas to couriers.
type ReplicaWriteReply struct {
	Cmds *Commands

	ErrorCode uint8
}

func (c *ReplicaWriteReply) ToBytes() []byte {
	out := make([]byte, cmdOverhead+replicaMessageReplyLength)
	out[0] = byte(replicaWriteReply)
	binary.BigEndian.PutUint32(out[2:6], replicaWriteReplyLength)
	out[6] = c.ErrorCode

	// optional traffic padding
	if c.Cmds == nil {
		return out
	}
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

// ReplicaMessage used over wire protocol from couriers to replicas,
// one replica at a time.
type ReplicaMessage struct {
	Cmds   *Commands
	Geo    *geo.Geometry
	Scheme nike.Scheme

	SenderEPubKey []byte
	DEK           *[32]byte
	Ciphertext    []byte
}

func (c *ReplicaMessage) ToBytes() []byte {
	out := make([]byte, cmdOverhead, cmdOverhead+32+len(c.Ciphertext))
	out[0] = byte(replicaMessage)
	binary.BigEndian.PutUint32(out[2:6], uint32(c.Length()-cmdOverhead))

	out = append(out, c.SenderEPubKey[:]...)
	out = append(out, c.DEK[:]...)
	out = append(out, c.Ciphertext...)

	return c.Cmds.padToMaxCommandSize(out, true)
}

func replicaMessageFromBytes(b []byte, cmds *Commands) (Command, error) {
	c := new(ReplicaMessage)
	c.Cmds = cmds
	c.Scheme = cmds.replicaNikeScheme

	c.SenderEPubKey = make([]byte, HybridKeySize(c.Scheme))
	copy(c.SenderEPubKey[:], b[:HybridKeySize(c.Scheme)])

	c.DEK = &[32]byte{}
	copy(c.DEK[:], b[HybridKeySize(c.Scheme):HybridKeySize(c.Scheme)+32])

	// c.Cmds.geo.PacketLength
	c.Ciphertext = make([]byte, len(b[HybridKeySize(c.Scheme)+32:]))
	copy(c.Ciphertext, b[HybridKeySize(c.Scheme)+32:])

	return c, nil
}

func (c *ReplicaMessage) Length() int {
	// XXX replace c.Geo.PacketLength with the precise payload size
	const dekLen = 32
	return cmdOverhead + dekLen + HybridKeySize(c.Scheme) + c.Geo.PacketLength
}

// ReplicaMessageReply is sent by replicas to couriers as a reply
// to the ReplicaMessage command.
type ReplicaMessageReply struct {
	Cmds *Commands

	ErrorCode     uint8
	EnvelopeHash  *[32]byte
	EnvelopeReply []byte
}

func (c *ReplicaMessageReply) ToBytes() []byte {
	out := make([]byte, cmdOverhead, cmdOverhead+1+32+len(c.EnvelopeReply))
	out[0] = byte(replicaMessageReply)
	binary.BigEndian.PutUint32(out[2:6], uint32(1+32+len(c.EnvelopeReply)))

	out = append(out, c.ErrorCode)
	out = append(out, c.EnvelopeHash[:]...)
	out = append(out, c.EnvelopeReply...)

	return c.Cmds.padToMaxCommandSize(out, true)
}

func replicaMessageReplyFromBytes(b []byte) (Command, error) {
	if len(b) != postDescriptorStatusLength {
		return nil, errInvalidCommand
	}

	r := new(ReplicaMessageReply)
	r.ErrorCode = b[0]

	r.EnvelopeHash = &[32]byte{}
	copy(r.EnvelopeHash[:], b[1:1+32])

	r.EnvelopeReply = make([]byte, len(b[1+32:]))
	copy(r.EnvelopeReply, b[1+32:])

	return r, nil
}

func (c *ReplicaMessageReply) Length() int {
	const (
		errorCodeLen  = 1
		idLen         = 32
		sigLen        = 32
		signatureSize = 32
	)
	replicaReadReplyLength := cmdOverhead + errorCodeLen + idLen + sigLen + signatureSize + c.Cmds.geo.PacketLength
	return cmdOverhead + 1 + 32 + replicaReadReplyLength
}

// SPDX-FileCopyrightText: Copyright (C) 2024  David Anthony Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package commands

import (
	"encoding/binary"
	"fmt"

	"github.com/katzenpost/hpqc/bacap"
	"github.com/katzenpost/hpqc/kem/mkem"
	"github.com/katzenpost/hpqc/nike"

	"github.com/katzenpost/katzenpost/core/sphinx/geo"
)

// HybridKeySize is a helper function which is used in our
// geometry calculations below.
func HybridKeySize(scheme nike.Scheme) int {
	// NIKE scheme CTIDH1024-X25519 has 160 byte public keys
	return scheme.PublicKeySize()

}

// ReplicaWrite has two distinct uses. Firstly, it is
// to be used directly on the wire for replication between replicas.
// Secondly, it can be embedded inside a ReplicaMessage which of course
// are sent from couriers to replicas.
type ReplicaWrite struct {

	// Cmds is set to nil if you want to serialize this type
	// without padding.
	Cmds *Commands

	BoxID     *[bacap.BoxIDSize]byte
	Signature *[bacap.SignatureSize]byte
	Payload   []byte
}

func (c *ReplicaWrite) ToBytes() []byte {
	const (
		uint32len   = 4
		cmdFrontLen = bacap.BoxIDSize + bacap.SignatureSize + uint32len
	)
	if c.Payload == nil {
		panic("ReplicaWrite.Payload ")
	}
	out := make([]byte, cmdOverhead, cmdOverhead+cmdFrontLen+len(c.Payload))
	out[0] = byte(replicaWrite)
	binary.BigEndian.PutUint32(out[2:6], uint32(cmdFrontLen+len(c.Payload)))

	out = append(out, c.BoxID[:]...)
	out = append(out, c.Signature[:]...)
	payloadLen := make([]byte, uint32len)
	binary.BigEndian.PutUint32(payloadLen, uint32(len(c.Payload)))
	out = append(out, payloadLen...)
	out = append(out, c.Payload...)

	// optional traffic padding
	if c.Cmds == nil {
		return out
	}
	return c.Cmds.padToMaxCommandSize(out, true)
}

func (c *ReplicaWrite) Length() int {
	// XXX FIX ME: largest ideal command size goes here
	var payloadSize = c.Cmds.geo.PacketLength
	return cmdOverhead + payloadSize + bacap.SignatureSize + bacap.BoxIDSize
}

func replicaWriteFromBytes(b []byte, cmds *Commands) (Command, error) {
	const uint32len = 4
	c := new(ReplicaWrite)
	c.Cmds = cmds
	c.BoxID = &[bacap.BoxIDSize]byte{}
	copy(c.BoxID[:], b[:bacap.BoxIDSize])
	c.Signature = &[bacap.SignatureSize]byte{}
	copy(c.Signature[:], b[bacap.BoxIDSize:bacap.BoxIDSize+bacap.SignatureSize])
	payloadLen := binary.BigEndian.Uint32(b[bacap.BoxIDSize+bacap.SignatureSize : bacap.BoxIDSize+bacap.SignatureSize+uint32len])
	c.Payload = make([]byte, payloadLen)
	copy(c.Payload, b[bacap.BoxIDSize+bacap.SignatureSize+uint32len:bacap.BoxIDSize+bacap.SignatureSize+uint32len+int(payloadLen)])
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
	DEK           *[mkem.DEKSize]byte
	Ciphertext    []byte
}

func (c *ReplicaMessage) ToBytes() []byte {
	out := make([]byte, cmdOverhead, cmdOverhead+32+len(c.Ciphertext))
	out[0] = byte(replicaMessage)
	binary.BigEndian.PutUint32(out[2:6], uint32(c.Length()-cmdOverhead))

	c.DEK = &[mkem.DEKSize]byte{}
	out = append(out, c.SenderEPubKey[:]...)
	c.DEK = &[mkem.DEKSize]byte{}
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

	c.DEK = &[mkem.DEKSize]byte{}
	copy(c.DEK[:], b[HybridKeySize(c.Scheme):HybridKeySize(c.Scheme)+mkem.DEKSize])

	c.Ciphertext = make([]byte, len(b[HybridKeySize(c.Scheme)+mkem.DEKSize:]))
	copy(c.Ciphertext, b[HybridKeySize(c.Scheme)+mkem.DEKSize:])

	return c, nil
}

func (c *ReplicaMessage) Length() int {
	// XXX replace c.Geo.PacketLength with the precise payload size
	return cmdOverhead + mkem.DEKSize + HybridKeySize(c.Scheme) + c.Geo.PacketLength
}

// ReplicaMessageReply is sent by replicas to couriers as a reply
// to the ReplicaMessage command.
type ReplicaMessageReply struct {
	Cmds *Commands

	// ErrorCode indicates failure on non-zero.
	ErrorCode uint8

	// EnvelopeHash identifies which query the request is replying to.
	EnvelopeHash *[32]byte

	// ReplicaID identifies the replica replying.
	ReplicaID uint8

	// EnvelopeReply contains the mkem ciphertext reply.
	EnvelopeReply []byte
}

func (c *ReplicaMessageReply) ToBytes() []byte {
	out := make([]byte, cmdOverhead, cmdOverhead+1+32+1+len(c.EnvelopeReply))
	out[0] = byte(replicaMessageReply)
	binary.BigEndian.PutUint32(out[2:6], uint32(1+32+1+len(c.EnvelopeReply)))

	fmt.Printf("writing ErrorCode %d\n", c.ErrorCode)
	out = append(out, c.ErrorCode)
	out = append(out, c.EnvelopeHash[:]...)
	out = append(out, c.ReplicaID)
	out = append(out, c.EnvelopeReply...)

	// optional traffic padding
	if c.Cmds == nil {
		return out
	}
	return c.Cmds.padToMaxCommandSize(out, false)
}

func replicaMessageReplyFromBytes(b []byte, cmds *Commands) (Command, error) {
	r := new(ReplicaMessageReply)
	r.Cmds = cmds
	r.ErrorCode = b[0]
	fmt.Printf("raw hex %x\n", b)

	r.EnvelopeHash = &[32]byte{}
	copy(r.EnvelopeHash[:], b[1:1+32])

	r.ReplicaID = b[1+32]

	r.EnvelopeReply = make([]byte, len(b[1+32+1:]))
	copy(r.EnvelopeReply, b[1+32+1:])

	return r, nil
}

func (c *ReplicaMessageReply) Length() int {
	return cmdOverhead + 1 + 32 + 1 + len(c.EnvelopeReply)
}

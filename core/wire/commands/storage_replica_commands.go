// SPDX-FileCopyrightText: Copyright (C) 2024  David Anthony Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package commands

import (
	"encoding/binary"
	"fmt"

	"golang.org/x/crypto/blake2b"

	"github.com/katzenpost/hpqc/bacap"
	"github.com/katzenpost/hpqc/hash"
	"github.com/katzenpost/hpqc/kem/mkem"
	"github.com/katzenpost/hpqc/nike"

	pgeo "github.com/katzenpost/katzenpost/pigeonhole/geo"
)

/****

NOTES ON TRAFFIC PADDING SCHEME FOR PQ NOISE WIRE PROTOCOL
----------------------------------------------------------

Outside of the mixnet the Pigeonhole system has 3 distinct sets of wire protocol
commands:

1. courier to replica
    * ReplicaMessage: Always padded. Sent from Courier to Replica only.
2. replica to courier
    * ReplicaMessageReply: Always padded. Sent from Replica to Courier only.
3. replica to replica
    * ReplicaWrite: If embeded in a ReplicaMessage there is no padding.
      Othewise it is sent between Replicas and MUST be padded.
    * ReplicaWriteReply: If embeded in a ReplicaMessageReply there is no padding.
      Othewise it is sent between Replicas and MUST be padded.

However because of the limitations of our PQ Noise wire protocol implementation,
we cannot create a listener that uses two sets of commands which is what's needed for
a replica to use one set of commands to talk to other replicas and another command set
for talking to couriers. Therefore we merge all three command sets into one set of
commands where they are all traffic padded to the size of the largest command.

Additionally we define the ReplicaDecoy command which is used by both replicas and couriers
as a decoy message. After PQ Noise encryption it will be indistinguishable from the other
commands, as they will all be uniformly padded to the same size.

****/

// HybridKeySize is a helper function which is used in our
// geometry calculations below.
func HybridKeySize(scheme nike.Scheme) int {
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

	// PigeonholeGeometry is used to calculate the precise payload size
	// for padding. Set to nil if you don't want padding.
	PigeonholeGeometry *pgeo.Geometry

	BoxID     *[bacap.BoxIDSize]byte
	Signature *[bacap.SignatureSize]byte
	Payload   []byte
}

func (c *ReplicaWrite) String() string { return "ReplicaWrite" }

func (c *ReplicaWrite) ToBytes() []byte {
	var cmdLen = bacap.BoxIDSize + bacap.SignatureSize + len(c.Payload)

	if c.Payload == nil {
		panic("ReplicaWrite.Payload ")
	}
	out := make([]byte, cmdOverhead, cmdOverhead+cmdLen)
	out[0] = byte(replicaWrite)
	out[1] = 0
	binary.BigEndian.PutUint32(out[2:6], uint32(cmdLen))

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
	var payloadSize = c.PigeonholeGeometry.CalculateBoxCiphertextLength()
	return cmdOverhead + bacap.BoxIDSize + bacap.SignatureSize + payloadSize
}

func replicaWriteFromBytes(b []byte, cmds *Commands) (Command, error) {
	c := new(ReplicaWrite)
	c.Cmds = cmds
	c.BoxID = &[bacap.BoxIDSize]byte{}
	copy(c.BoxID[:], b[:bacap.BoxIDSize])
	c.Signature = &[bacap.SignatureSize]byte{}
	copy(c.Signature[:], b[bacap.BoxIDSize:bacap.BoxIDSize+bacap.SignatureSize])
	c.Payload = make([]byte, len(b[bacap.BoxIDSize+bacap.SignatureSize:]))
	copy(c.Payload, b[bacap.BoxIDSize+bacap.SignatureSize:])
	return c, nil
}

// ReplicaWriteReply can facilitate replication between replicas as the
// reply to the ReplicaWrite command. Otherwise it is embedded in a
// ReplicaMessageReply and sent from replicas to couriers.
type ReplicaWriteReply struct {
	Cmds *Commands

	ErrorCode uint8
}

func (c *ReplicaWriteReply) String() string { return "ReplicaWriteReply" }

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
	return cmdOverhead + replicaWriteReplyLength
}

// ReplicaDecoy is a decoy message type used by replicas and couriers.
type ReplicaDecoy struct {
	Cmds *Commands
}

func (c *ReplicaDecoy) String() string { return "ReplicaDecoy" }

func (c *ReplicaDecoy) ToBytes() []byte {
	out := make([]byte, cmdOverhead)
	out[0] = byte(replicaDecoy)

	// optional traffic padding
	if c.Cmds == nil {
		return out
	}
	return c.Cmds.padToMaxCommandSize(out, true)
}

func (c *ReplicaDecoy) Length() int {
	return cmdOverhead
}

func replicaDecoyFromBytes(b []byte, cmds *Commands) (Command, error) {
	r := new(ReplicaDecoy)
	r.Cmds = cmds
	return r, nil
}

// ReplicaMessage used over wire protocol from couriers to replicas,
// one replica at a time.
type ReplicaMessage struct {
	Cmds               *Commands
	PigeonholeGeometry *pgeo.Geometry
	Scheme             nike.Scheme

	SenderEPubKey []byte
	DEK           *[mkem.DEKSize]byte
	Ciphertext    []byte
}

func (c *ReplicaMessage) String() string { return "ReplicaMessage" }

func (c *ReplicaMessage) EnvelopeHash() *[hash.HashSize]byte {
	h, err := blake2b.New256(nil)
	if err != nil {
		panic(err)
	}
	_, err = h.Write(c.SenderEPubKey)
	if err != nil {
		panic(err)
	}
	_, err = h.Write(c.Ciphertext)
	if err != nil {
		panic(err)
	}
	s := h.Sum([]byte{})
	hashOut := &[blake2b.Size256]byte{}
	copy(hashOut[:], s)
	return hashOut
}

func (c *ReplicaMessage) ToBytes() []byte {
	hkSize := len(c.SenderEPubKey)

	// Validate that DEK is not nil to prevent panic
	if c.DEK == nil {
		panic("ReplicaMessage.ToBytes: DEK field is nil")
	}

	out := make([]byte, cmdOverhead)
	out[0] = byte(replicaMessage)
	out[1] = 0
	totalLen := hkSize + mkem.DEKSize + len(c.Ciphertext)
	binary.BigEndian.PutUint32(out[2:6], uint32(totalLen))

	out = append(out, c.SenderEPubKey...)
	out = append(out, c.DEK[:]...)
	out = append(out, c.Ciphertext...)

	// optional traffic padding
	if c.Cmds == nil {
		return out
	}
	return c.Cmds.padToMaxCommandSize(out, true)
}

func replicaMessageFromBytes(b []byte, cmds *Commands) (Command, error) {
	const uint32len = 4

	c := new(ReplicaMessage)
	c.Cmds = cmds
	c.Scheme = cmds.replicaNikeScheme

	hkSize := HybridKeySize(c.Scheme)
	offset := 0

	if len(b) < hkSize+mkem.DEKSize+uint32len {
		return nil, fmt.Errorf("message too short")
	}

	c.SenderEPubKey = make([]byte, hkSize)
	copy(c.SenderEPubKey, b[offset:offset+hkSize])
	offset += hkSize

	c.DEK = new([mkem.DEKSize]byte)
	copy(c.DEK[:], b[offset:offset+mkem.DEKSize])
	offset += mkem.DEKSize

	c.Ciphertext = make([]byte, len(b[offset:]))
	copy(c.Ciphertext, b[offset:])

	return c, nil
}

// Length is the largest possible length of a ReplicaMessage.
func (c *ReplicaMessage) Length() int {
	ciphertextLen := c.PigeonholeGeometry.CalculateCourierEnvelopeCiphertextSizeWrite()
	return cmdOverhead + mkem.DEKSize + HybridKeySize(c.Scheme) + ciphertextLen
}

// ReplicaMessageReply is sent by replicas to couriers as a reply
// to the ReplicaMessage command.
type ReplicaMessageReply struct {
	Cmds *Commands

	PigeonholeGeometry *pgeo.Geometry

	// ErrorCode indicates failure on non-zero.
	ErrorCode uint8

	// EnvelopeHash identifies which query the request is replying to.
	EnvelopeHash *[32]byte

	// ReplicaID identifies the replica replying.
	ReplicaID uint8

	// IsRead indicates whether the request was a read operation.
	IsRead bool

	// EnvelopeReply contains the mkem ciphertext reply.
	EnvelopeReply []byte
}

func (c *ReplicaMessageReply) String() string { return "ReplicaMessageReply" }

func (c *ReplicaMessageReply) ToBytes() []byte {
	out := make([]byte, cmdOverhead, cmdOverhead+1+32+1+1+len(c.EnvelopeReply))
	out[0] = byte(replicaMessageReply)
	binary.BigEndian.PutUint32(out[2:6], uint32(1+32+1+1+len(c.EnvelopeReply)))

	out = append(out, c.ErrorCode)
	out = append(out, c.EnvelopeHash[:]...)
	out = append(out, c.ReplicaID)
	if c.IsRead {
		out = append(out, 1)
	} else {
		out = append(out, 0)
	}
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

	r.EnvelopeHash = &[32]byte{}
	copy(r.EnvelopeHash[:], b[1:1+32])

	r.ReplicaID = b[1+32]
	r.IsRead = b[1+32+1] == 1

	r.EnvelopeReply = make([]byte, len(b[1+32+1+1:]))
	copy(r.EnvelopeReply, b[1+32+1+1:])

	return r, nil
}

// Length calculates the largest possible length of a ReplicaMessageReply.
func (c *ReplicaMessageReply) Length() int {
	return cmdOverhead + 1 + 32 + 1 + 1 + c.PigeonholeGeometry.CalculateEnvelopeReplySizeRead()
}

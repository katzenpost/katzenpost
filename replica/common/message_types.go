// SPDX-FileCopyrightText: © 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package common

import (
	cbor "github.com/fxamacker/cbor/v2"

	"github.com/katzenpost/hpqc/bacap"
	"github.com/katzenpost/hpqc/hash"
	"github.com/katzenpost/hpqc/kem/mkem"

	"github.com/katzenpost/katzenpost/core/wire/commands"
)

// CourierEnvelope is sent from the Client to its Courier.
// CourierEnvelope is used when the Client is trying to either read or
// write a single BACAP box.
//
// NOTE that the SenderEPubKey and Ciphertext fields below
// get hashed to form the EnvelopeHash later used in ReplicaMessageReply.
type CourierEnvelope struct {
	// IntermediateReplicas are used to initially send the message
	// to, and eventually the message gets replicated to the
	// correct locations. This hides the correct locations from
	// the courier.
	IntermediateReplicas [2]uint8

	// DEK is used for each replica: ReplicaMessage.DEK
	DEK [2]*[mkem.DEKSize]byte

	// ReplyIndex is an actual index into the 2 element array of
	// intermediate replicas: the `IntermediateReplicas` field above.
	ReplyIndex uint8

	// SenderEPubKey is the sender's ephemeral public key.
	SenderEPubKey []byte

	// Ciphertext is the encrypted and MAC'ed payload.
	Ciphertext []byte
}

type envelopeHash struct {
	// SenderEPubKey is the sender's ephemeral public key.
	SenderEPubKey []byte

	// Ciphertext is the encrypted and MAC'ed payload.
	Ciphertext []byte
}

func (c *envelopeHash) Bytes() *[hash.HashSize]byte {
	blob, err := cbor.Marshal(c)
	if err != nil {
		panic(err) // impossible
	}

	h := hash.Sum256(blob)
	return &h
}

func (c *CourierEnvelope) EnvelopeHash() *[hash.HashSize]byte {
	env := &envelopeHash{
		SenderEPubKey: c.SenderEPubKey,
		Ciphertext:    c.Ciphertext,
	}
	return env.Bytes()
}

// Bytes serializes the given CourierEnvelope using CBOR.
func (c *CourierEnvelope) Bytes() []byte {
	blob, err := cbor.Marshal(c)
	if err != nil {
		panic(err)
	}
	return blob
}

// CourierEnvelopeFromBytes is a helper function to unmarshal
// a CBOR blob of type *CourierEnvelope.
func CourierEnvelopeFromBytes(b []byte) (*CourierEnvelope, error) {
	c := &CourierEnvelope{}
	_, err := cbor.UnmarshalFirst(b, c)
	if err != nil {
		return nil, err
	}
	return c, nil
}

// CourierEnvelopeReply us used when the Courier sends a reply to the client
// in response to some previously sent CourierEnvelope message.
type CourierEnvelopeReply struct {
	// EnvelopeHash is used to uniquely identify the CourierEnvelope message
	// that this CourierEnvelopeReply is replying to.
	EnvelopeHash *[hash.HashSize]byte

	// ReplyIndex is an actual index into the 2 element array of
	// intermediate replicas: the `IntermediateReplicas` field in
	// the original courier envelope.
	ReplyIndex uint8

	// Payload contains an embedded ReplicaMessageReply.
	Payload *commands.ReplicaMessageReply

	// ErrorString will be empty if the query was well formed. Otherwise
	// ErrorString will be set to an informative error string.
	ErrorString string

	// ErrorCode if non-zero indicates an error. ReplyIndex and Payload
	// maybe invalid if an error is indicated.
	ErrorCode uint8
}

// Bytes returns a CBOR blob of the given CourierEnvelopeReply.
func (c *CourierEnvelopeReply) Bytes() []byte {
	blob, err := cbor.Marshal(c)
	if err != nil {
		panic(err)
	}
	return blob
}

// CourierEnvelopeReplyFromBytes is a helper function to unmarshal
// a CBOR blob of type *CourierEnvelopeReply.
func CourierEnvelopeReplyFromBytes(b []byte) (*CourierEnvelopeReply, error) {
	c := &CourierEnvelopeReply{}
	_, err := cbor.UnmarshalFirst(b, c)
	if err != nil {
		return nil, err
	}
	return c, nil
}

// ReplicaInnerMessage is a type that is used to encapsulate either a
// ReplicaRead or a ReplicaWrite.
type ReplicaInnerMessage struct {
	ReplicaRead  *ReplicaRead
	ReplicaWrite *commands.ReplicaWrite
}

func (c *ReplicaInnerMessage) Bytes() []byte {
	if c.ReplicaRead != nil && c.ReplicaWrite != nil {
		panic("ReplicaInnerMessage.Bytes failure: one field must be nil.")
	}
	blob, err := cbor.Marshal(c)
	if err != nil {
		panic(err)
	}
	return blob
}

func ReplicaInnerMessageFromBytes(b []byte) (*ReplicaInnerMessage, error) {
	c := &ReplicaInnerMessage{}
	err := cbor.Unmarshal(b, c)
	if err != nil {
		return nil, err
	}
	return c, nil
}

// ReplicaRead isn't used directly on the wire protocol
// but is embedded inside the ReplicaMessage which of course
// are sent by the couriers to the replicas.
type ReplicaRead struct {
	BoxID *[bacap.BoxIDSize]byte
}

func (c *ReplicaRead) Length() int {
	return 32
}

func (c *ReplicaRead) ToBytes() []byte {
	return c.Bytes()
}

// Bytes marshals the given ReplicaRead into
// a CBOR binary blob.
func (c *ReplicaRead) Bytes() []byte {
	blob, err := cbor.Marshal(c)
	if err != nil {
		panic(err) // impossible
	}
	return blob
}

// ReplicaReadFromBytes unmarshals the given CBOR binary blob
// into a ReplicaRead type.
func ReplicaReadFromBytes(b []byte) (*ReplicaRead, error) {
	c := &ReplicaRead{}
	_, err := cbor.UnmarshalFirst(b, c)
	if err != nil {
		return nil, err
	}
	return c, nil
}

// ReplicaReadReply isn't used directly on the wire protocol
// but is embedded inside the ReplicaMessageReply which of course
// are sent by the replicas to the couriers. Therefore the
// ReplicaReadReply command is never padded because it is always
// encapsulated by the ReplicaMessageReply which is padded.
type ReplicaReadReply struct {

	// ErrorCode indicates an error.
	ErrorCode uint8

	// BoxID uniquely identifies a box.
	BoxID *[bacap.BoxIDSize]byte

	// Signature covers the given Payload field and
	// is verifiable with the BoxID which is also the public key.
	Signature *[bacap.SignatureSize]byte

	// Payload is encrypted and MAC'ed.
	Payload []byte
}

// Bytes is a helper method used to marshal the
// given ReplicaReadReply into a CBOR binary blob.
func (c *ReplicaReadReply) Bytes() []byte {
	blob, err := cbor.Marshal(c)
	if err != nil {
		panic(err)
	}
	return blob
}

// ReplicaReadReplyFromBytes is a helper function used to unmarshal
// the given CBOR binary blob into a *ReplicaReadReply type.
func ReplicaReadReplyFromBytes(b []byte) (*ReplicaReadReply, error) {
	c := &ReplicaReadReply{}
	err := cbor.Unmarshal(b, c)
	if err != nil {
		return nil, err
	}
	return c, nil
}

// ReplicaMessageReplyInnerMessage is the struct type
// which is CBOR encoded, encrypted and sent from
// replica to courier service inside a ReplicaMessageReply.
// It encapsulates either a ReplicaReadReply or a ReplicaWriteReply.
type ReplicaMessageReplyInnerMessage struct {
	// ReplicaReadReply is of type *ReplicaReadReply.
	ReplicaReadReply *ReplicaReadReply

	// ReplicaWriteReply is of type *ReplicaWriteReply.
	ReplicaWriteReply *commands.ReplicaWriteReply
}

// ReplicaMessageReplyInnerMessage CBOR encode the given type.
func (c *ReplicaMessageReplyInnerMessage) Bytes() []byte {
	if c.ReplicaReadReply != nil && c.ReplicaWriteReply != nil {
		panic("ReplicaMessageReplyInnerMessage.Bytes failure: one field must be nil.")
	}
	blob, err := cbor.Marshal(c)
	if err != nil {
		panic(err)
	}
	return blob
}

// ReplicaMessageReplyInnerMessageFromBytes CBOR decodes the binary blob.
func ReplicaMessageReplyInnerMessageFromBytes(b []byte) (*ReplicaMessageReplyInnerMessage, error) {
	c := &ReplicaMessageReplyInnerMessage{}
	err := cbor.Unmarshal(b, c)
	if err != nil {
		return nil, err
	}
	return c, nil
}

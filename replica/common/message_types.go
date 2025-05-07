// SPDX-FileCopyrightText: © 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package common

import (
	cbor "github.com/fxamacker/cbor/v2"

	"github.com/katzenpost/hpqc/hash"
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
	DEK [2]*[32]byte

	// ReplyIndex is described:
	// The client will be resending its messages to the courier
	// until it receives a reply. The courier is responsible for
	// NOT sending each of those resent messages to the
	// replicas. It can use the EnvelopeHash to deduplicate.  When
	// the client sends a CourierEnvelope that the courier has
	// already got ReplicaMessageReply's for, the courier needs to
	// respond with one of those.  ReplyIndex will let the client
	// choose which one. I guess it could be a bool.
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

func (c *envelopeHash) Bytes() *[32]byte {
	blob, err := cbor.Marshal(c)
	if err != nil {
		panic(err) // impossible
	}

	h := hash.Sum256(blob)
	return &h
}

func (c *CourierEnvelope) EnvelopeHash() *[32]byte {
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

// CourierEnvelopeReply us used wher the Courier sends a reply to the client
// in response to some previously sent CourierEnvelope message.
type CourierEnvelopeReply struct {
	// EnvelopeHash is used to uniquely identify the CourierEnvelope message
	// that this CourierEnvelopeReply is replying to.
	EnvelopeHash *[32]byte

	// ReplyIndex is a copy of the CourierEnvelope.ReplyIndex field from the
	// CourierEnvelope that this CourierEnvelopeReply corresponds to
	ReplyIndex uint8

	// Payload contains an embedded ReplicaMessageReply.
	Payload *commands.ReplicaMessageReply

	// ErrorString will be empty if the query was well formed. Otherwise
	// ErrorString will be set to an informative error string.
	ErrorString string
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

// ReplicaRead isn't used directly on the wire protocol
// but is embedded inside the ReplicaMessage which of course
// are sent by the couriers to the replicas.
type ReplicaRead struct {
	BoxID *[32]byte
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
	BoxID *[32]byte

	// Signature covers the given Payload field and
	// is verifiable with the BoxID which is also the public key.
	Signature *[32]byte

	// Payload is the encrypted and MAC'ed.
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

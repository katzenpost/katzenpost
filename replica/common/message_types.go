// SPDX-FileCopyrightText: © 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package common

import (
	cbor "github.com/fxamacker/cbor/v2"
	"golang.org/x/crypto/blake2b"

	"github.com/katzenpost/hpqc/bacap"
	"github.com/katzenpost/hpqc/hash"
	"github.com/katzenpost/hpqc/kem/mkem"

	"github.com/katzenpost/katzenpost/core/wire/commands"
)

// CourierQuery is sent from the Client to its Courier.
type CourierQuery struct {
	CourierEnvelope *CourierEnvelope
	CopyCommand     *CopyCommand
}

// Bytes serializes the given CourierEnvelope using CBOR.
func (c *CourierQuery) Bytes() []byte {
	blob, err := ccbor.Marshal(c)
	if err != nil {
		panic(err)
	}
	return blob
}

// CourierQueryFromBytes is a helper function to unmarshal
// a CBOR blob of type *CourierQuery.
func CourierQueryFromBytes(b []byte) (*CourierQuery, error) {
	c := &CourierQuery{}
	_, err := cbor.UnmarshalFirst(b, c)
	if err != nil {
		return nil, err
	}
	return c, nil
}

// CourierQueryReply is sent from the Courier to the Client.
type CourierQueryReply struct {
	CourierEnvelopeReply *CourierEnvelopeReply
	CopyCommandReply     *CopyCommandReply
}

// Bytes serializes the given CourierEnvelope using CBOR.
func (c *CourierQueryReply) Bytes() []byte {
	blob, err := ccbor.Marshal(c)
	if err != nil {
		panic(err)
	}
	return blob
}

// CourierQueryReplyFromBytes is a helper function to unmarshal
// a CBOR blob of type *CourierEnvelope.
func CourierQueryReplyFromBytes(b []byte) (*CourierQueryReply, error) {
	c := &CourierQueryReply{}
	_, err := cbor.UnmarshalFirst(b, c)
	if err != nil {
		return nil, err
	}
	return c, nil
}

// CopyCommand is used to tell the courier to read a temporary sequence which
// contains a series of write operations which are encrypted to the respective
// replicas. The courier cannot read these write operations, but it can proxy
// them to various specified intermediate replicas which will decrypt and
// execute them.
//
// The given WriteCap is used to derive a ReadCap which is used to read
// the temporary sequence. Then the courier proxies the sequenced operations
// to the specified intermediate replicas. The given WriteCap is then used
// to write tombstones to the temporary sequence to delete it.
type CopyCommand struct {
	WriteCap *bacap.BoxOwnerCap
}

// CopyCommandReply is sent by the courier in response to a CopyCommand
// AFTER the courier has executed the CopyCommand or an error was encountered.
// An ErrorCode of zero indicates success.
type CopyCommandReply struct {
	ErrorCode uint8
}

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

	// Epoch is the Katzenpost epoch in which the ReplyIndex is valid.
	// That is to say, you must retrieve the replica public key from the
	// PKI document for this epoch in order to verify and decrypt
	// the Ciphertext.
	Epoch uint64

	// SenderEPubKey is the sender's ephemeral public key.
	SenderEPubKey []byte

	// Ciphertext is the encrypted and MAC'ed payload.
	Ciphertext []byte

	// IsRead is set to true to indicate a read request.
	// Or else it is set to false indicating a write request.
	IsRead bool
}

// EnvelopeHash returns the hash of the CourierEnvelope.
func (c *CourierEnvelope) EnvelopeHash() *[hash.HashSize]byte {
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

// Bytes serializes the given CourierEnvelope using CBOR.
func (c *CourierEnvelope) Bytes() []byte {
	blob, err := ccbor.Marshal(c)
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

	// Payload contains an embedded ReplicaMessageReply's EnvelopeReply.
	Payload []byte

	// ErrorCode if non-zero indicates an error. ReplyIndex and Payload
	// maybe invalid if an error is indicated.
	ErrorCode uint8
}

// Bytes returns a CBOR blob of the given CourierEnvelopeReply.
func (c *CourierEnvelopeReply) Bytes() []byte {
	blob, err := ccbor.Marshal(c)
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

// Bytes returns a CBOR blob of the given ReplicaInnerMessage.
func (c *ReplicaInnerMessage) Bytes() []byte {
	if c.ReplicaRead != nil && c.ReplicaWrite != nil {
		panic("ReplicaInnerMessage.Bytes failure: one field must be nil.")
	}
	blob, err := ccbor.Marshal(c)
	if err != nil {
		panic(err)
	}
	return blob
}

// ReplicaInnerMessageFromBytes is a helper function to unmarshal
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
	blob, err := ccbor.Marshal(c)
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

	// IsLast indicates whether this is the last box in the sequence.
	// Most of the time this is unused. But it is used when reading
	// a temporary sequence of Boxes for the purpose of the Courier's
	// CopyCommand.
	IsLast bool
}

// Bytes is a helper method used to marshal the
// given ReplicaReadReply into a CBOR binary blob.
func (c *ReplicaReadReply) Bytes() []byte {
	blob, err := ccbor.Marshal(c)
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
	blob, err := ccbor.Marshal(c)
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

// Box is used only by our local state database.
type Box struct {
	BoxID     *[bacap.BoxIDSize]byte
	Signature *[bacap.SignatureSize]byte
	Payload   []byte
}

// Bytes returns a CBOR blob of the given Box.
func (c *Box) Bytes() []byte {
	blob, err := ccbor.Marshal(c)
	if err != nil {
		panic(err)
	}
	return blob
}

// BoxFromBytes unmarshals the given CBOR blob into a Box.
func BoxFromBytes(b []byte) (*Box, error) {
	c := &Box{}
	err := cbor.Unmarshal(b, c)
	if err != nil {
		return nil, err
	}
	return c, nil
}

func init() {
	var err error
	opts := cbor.CanonicalEncOptions()
	ccbor, err = opts.EncMode()
	if err != nil {
		panic(err)
	}
}

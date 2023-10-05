package common

import (
	"github.com/fxamacker/cbor/v2"
)

const (
	MapServiceName = "map"
)

type MapRequest struct {
	// ID is the ID of the block which is a ed25519 PublicKey
	ID MessageID

	// Future version may wish to include the PublicKey
	// if PublicKeySize is
	// Signature is the signature over Payload with
	// The Read or Write capability keys for the entry
	// identified by ID
	Signature []byte

	// Payload is the contents to store or nil
	Payload []byte
}

func (m *MapRequest) Marshal() ([]byte, error) {
	return cbor.Marshal(m)
}

func (m *MapRequest) Unmarshal(b []byte) error {
	return cbor.Unmarshal(b, m)
}

type MapStatus uint8

const (
	StatusOK MapStatus = iota
	StatusNotFound
	StatusFailed
)

type MapResponse struct {
	Status  MapStatus
	Payload []byte
}

func (m *MapResponse) Marshal() ([]byte, error) {
	return cbor.Marshal(m)
}

func (m *MapResponse) Unmarshal(b []byte) error {
	return cbor.Unmarshal(b, m)
}

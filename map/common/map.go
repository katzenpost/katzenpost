package common

import (
	"github.com/fxamacker/cbor/v2"
)

const (
	// MessageID keys are 32 bytes long and globally unique amongst all clients
	MessageIDLen   = 32
	MapServiceName = "map"
)

type MessageID [MessageIDLen]byte

type MapRequest struct {
	// TID is the temporary ID of the block
	TID MessageID
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

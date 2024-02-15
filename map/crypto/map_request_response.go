// SPDX-FileCopyrightText: Copyright (C) 2021 Masala
// SPDX-License-Identifier: AGPL-3.0-only

package crypto

import (
	"github.com/fxamacker/cbor/v2"
)

const (
	MapServiceName = "map"
)

type MapRequest struct {
	ReadCap  *ReadCapability
	WriteCap *WriteCapability
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

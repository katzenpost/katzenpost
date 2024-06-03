// Copyright (C) 2021  Masala
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package common

import (
	"github.com/fxamacker/cbor/v2"
)

const (
	PigeonHoleServiceName = "pigeonhole"
)

type PigeonHoleRequest struct {
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

func (m *PigeonHoleRequest) Marshal() ([]byte, error) {
	return cbor.Marshal(m)
}

func (m *PigeonHoleRequest) Unmarshal(b []byte) error {
	return cbor.Unmarshal(b, m)
}

type PigeonHoleStatus uint8

const (
	StatusOK PigeonHoleStatus = iota
	StatusNotFound
	StatusFailed
)

type PigeonHoleResponse struct {
	Status  PigeonHoleStatus
	Payload []byte
}

func (m *PigeonHoleResponse) Marshal() ([]byte, error) {
	return cbor.Marshal(m)
}

func (m *PigeonHoleResponse) Unmarshal(b []byte) error {
	return cbor.Unmarshal(b, m)
}

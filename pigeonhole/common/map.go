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
	"errors"
	"github.com/fxamacker/cbor/v2"
	"github.com/katzenpost/hpqc/sign/ed25519"
)

const (
	PigeonHoleServiceName = "pigeonhole"
)

type MessageID [ed25519.PublicKeySize]byte

type PigeonHoleRequest struct {
	// ID is the ID of the box which is a ed25519 PublicKey
	ID MessageID

	// Signature of the payload by the secret key corresponding to ID
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

var (
	ErrStatusNotFound = errors.New("StatusNotFound")
	ErrStatusFailed   = errors.New("StatusFailed")
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

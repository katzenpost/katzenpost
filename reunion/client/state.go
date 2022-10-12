// state.go - Reunion client state.
// Copyright (C) 2020  David Stainton.
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

// Package client provides the Reunion protocol client.
package client

import (
	"github.com/katzenpost/katzenpost/reunion/crypto"
	"github.com/fxamacker/cbor/v2"
)

type serializableExchange struct {
	Status           int
	ContactID        uint64
	ExchangeID       uint64
	Session          *crypto.Session
	SentT1           []byte
	SentT2Map        map[ExchangeHash][]byte
	ReceivedT1s      map[ExchangeHash][]byte
	ReceivedT2s      map[ExchangeHash][]byte
	ReceivedT3s      map[ExchangeHash][]byte
	RepliedT1s       map[ExchangeHash][]byte
	RepliedT2s       map[ExchangeHash][]byte
	ReceivedT1Alphas map[ExchangeHash]*crypto.PublicKey
	DecryptedT1Betas map[ExchangeHash]*crypto.PublicKey
}

func (s *serializableExchange) Unmarshal(data []byte) error {
	return cbor.Unmarshal(data, s)
}

func (s *serializableExchange) Marshal() ([]byte, error) {
	return cbor.Marshal(s)
}

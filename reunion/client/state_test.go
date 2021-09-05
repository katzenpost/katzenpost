// state_test.go - Reunion client state tests.
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
	"testing"

	"github.com/katzenpost/katzenpost/reunion/crypto"
	"github.com/stretchr/testify/require"
)

func TestSerializableExchange(t *testing.T) {
	require := require.New(t)

	session, err := crypto.NewSession([]byte{}, []byte{}, 0)
	require.NoError(err)

	s1 := serializableExchange{
		Status:           0,
		ContactID:        0,
		Session:          session,
		SentT1:           []byte{},
		SentT2Map:        make(map[ExchangeHash][]byte),
		ReceivedT1s:      make(map[ExchangeHash][]byte),
		ReceivedT2s:      make(map[ExchangeHash][]byte),
		ReceivedT3s:      make(map[ExchangeHash][]byte),
		RepliedT1s:       make(map[ExchangeHash][]byte),
		RepliedT2s:       make(map[ExchangeHash][]byte),
		ReceivedT1Alphas: make(map[ExchangeHash]*crypto.PublicKey),
		DecryptedT1Betas: make(map[ExchangeHash]*crypto.PublicKey),
	}

	ss, err := s1.Marshal()
	require.NoError(err)

	s2 := serializableExchange{
		Status:           0,
		ContactID:        0,
		Session:          session,
		SentT1:           []byte{},
		SentT2Map:        make(map[ExchangeHash][]byte),
		ReceivedT1s:      make(map[ExchangeHash][]byte),
		ReceivedT2s:      make(map[ExchangeHash][]byte),
		ReceivedT3s:      make(map[ExchangeHash][]byte),
		RepliedT1s:       make(map[ExchangeHash][]byte),
		RepliedT2s:       make(map[ExchangeHash][]byte),
		ReceivedT1Alphas: make(map[ExchangeHash]*crypto.PublicKey),
		DecryptedT1Betas: make(map[ExchangeHash]*crypto.PublicKey),
	}

	err = s2.Unmarshal(ss)
	require.NoError(err)

	xx, err := s2.Marshal()
	require.NoError(err)

	s3 := serializableExchange{
		Status:           0,
		ContactID:        0,
		Session:          session,
		SentT1:           []byte{},
		SentT2Map:        make(map[ExchangeHash][]byte),
		ReceivedT1s:      make(map[ExchangeHash][]byte),
		ReceivedT2s:      make(map[ExchangeHash][]byte),
		ReceivedT3s:      make(map[ExchangeHash][]byte),
		RepliedT1s:       make(map[ExchangeHash][]byte),
		RepliedT2s:       make(map[ExchangeHash][]byte),
		ReceivedT1Alphas: make(map[ExchangeHash]*crypto.PublicKey),
		DecryptedT1Betas: make(map[ExchangeHash]*crypto.PublicKey),
	}

	err = s3.Unmarshal(xx)
	require.NoError(err)

	zz, err := s3.Marshal()
	require.NoError(err)

	require.Equal(xx, zz)
}

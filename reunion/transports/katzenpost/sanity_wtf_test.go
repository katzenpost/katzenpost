// sanity_wtf_test.go - tests
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

package katzenpost

import (
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/crypto/nike/ecdh"
	"github.com/katzenpost/katzenpost/core/crypto/rand"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/katzenpost/katzenpost/server/cborplugin"
)

func TestSerializationSanity(t *testing.T) {
	require := require.New(t)

	reply := cborplugin.Response{
		Payload: []byte("yo, what's up?"),
	}
	serialized, err := cbor.Marshal(reply)
	require.NoError(err)

	mynike := ecdh.NewEcdhNike(rand.Reader)
	nrHops := 5
	geo := geo.GeometryFromUserForwardPayloadLength(mynike, 2000, true, nrHops)

	payload := make([]byte, geo.UserForwardPayloadLength)
	copy(payload, serialized)

	response := cborplugin.Response{
		Payload: make([]byte, 0),
	}
	err = cbor.Unmarshal(payload, &response)
	require.NoError(err)

	t.Logf("%s", response.Payload)
}

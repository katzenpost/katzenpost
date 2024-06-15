// client_test.go - map service client tests
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

package client

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDuplexCapsFromSeed(t *testing.T) {
	require := require.New(t)

	alice_read, alice_write := duplexCapsFromSeed(true, []byte("secret"))
	bob_read, bob_write := duplexCapsFromSeed(false, []byte("secret"))

	require.Equal(alice_read.Addr([]byte("address1")), bob_write.Addr([]byte("address1")))
	require.Equal(bob_read.Addr([]byte("address1")), alice_write.Addr([]byte("address1")))
	require.NotEqual(alice_read.Addr([]byte("address1")), alice_write.Addr([]byte("address1")))

}

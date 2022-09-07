// kem_test.go - Wire protocol session KEM interfaces.
// Copyright (C) 2022  David Anthony Stainton
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

// Package wire implements the Katzenpost wire protocol.
package wire

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/crypto/rand"
)

func TestKEMPEM(t *testing.T) {
	privFile := "client_priv_key.pem"
	pubFile := "client_pub_key.pem"
	privKey, err := NewScheme().Load(privFile, pubFile, rand.Reader)
	require.NoError(t, err)

	privKey2, err := NewScheme().Load(privFile, pubFile, nil)
	require.NoError(t, err)

	require.Equal(t, privKey.Bytes(), privKey2.Bytes())

	pubFile2 := "client_pub_key2.pem"
	err = privKey2.PublicKey().ToPEMFile(pubFile2)
	require.NoError(t, err)
}

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
	"github.com/katzenpost/katzenpost/core/crypto/eddsa"
	"github.com/katzenpost/katzenpost/core/crypto/rand"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestCreateRWCap(t *testing.T) {
	require := require.New(t)
	// create a capability key
	pk, err := eddsa.NewKeypair(rand.Reader)
	require.NoError(err)

	rwCap := NewRWCap(pk)
	addr := []byte("we can use whatever byte sequence we like as address here")
	id := rwCap.Addr(addr)
	wKey := rwCap.Write(addr)
	require.Equal(wKey.PublicKey().Bytes(), id.WritePk().Bytes())

	rKey := rwCap.Read(addr)
	require.Equal(rKey.PublicKey().Bytes(), id.ReadPk().Bytes())
}

func TestCreateROCap(t *testing.T) {
	require := require.New(t)
	// create a capability key
	pk, err := eddsa.NewKeypair(rand.Reader)
	require.NoError(err)

	rwCap := NewRWCap(pk)
	addr := []byte("we can use whatever byte sequence we like as address here")
	id := rwCap.Addr(addr)
	wKey := rwCap.Write(addr)
	require.Equal(wKey.PublicKey().Bytes(), id.WritePk().Bytes())

	rKey := rwCap.Read(addr)
	require.Equal(rKey.PublicKey().Bytes(), id.ReadPk().Bytes())
}

func TestCreateWOCap(t *testing.T) {
	require := require.New(t)
	// create a capability key
	sk, err := eddsa.NewKeypair(rand.Reader)
	require.NoError(err)
	pRoot := sk.PublicKey()

	woCap := NewWOCap(pRoot, sk.Blind(WriteCap))
	addr := []byte("we can use whatever byte sequence we like as address here")
	id := woCap.Addr(addr)
	wKey := woCap.Write(addr)
	require.Equal(wKey.PublicKey().Bytes(), id.WritePk().Bytes())
}

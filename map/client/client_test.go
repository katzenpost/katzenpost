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
//go:build docker_test
// +build docker_test

package client

import (
	"context"
	"io"
	"testing"

	"github.com/katzenpost/katzenpost/client"
	"github.com/katzenpost/katzenpost/client/config"
	"github.com/katzenpost/katzenpost/core/crypto/eddsa"
	"github.com/katzenpost/katzenpost/core/crypto/rand"
	"github.com/katzenpost/katzenpost/map/common"
	"github.com/stretchr/testify/require"
)

func TestCreateMap(t *testing.T) {
	require := require.New(t)

	cfg, err := config.LoadFile("testdata/client.toml")
	require.NoError(err)

	client, err := client.New(cfg)
	require.NoError(err)

	ctx := context.Background()
	session, err := client.NewTOFUSession(ctx)
	require.NoError(err)
	session.WaitForDocument(ctx)

	c, err := NewClient(session)
	require.NoError(err)
	require.NotNil(c)

	// test creating and retrieving an item

	// create a capability key
	pk, err := eddsa.NewKeypair(rand.Reader)
	require.NoError(err)
	rwCap := common.NewRWCap(pk)

	// get the id and writeKey for an addrress
	addr := make([]byte, 32)
	_, err = io.ReadFull(rand.Reader, addr)
	require.NoError(err)
	id := rwCap.Addr(addr)
	wKey := rwCap.WriteKey(addr)

	// make sure that the verifier of id matches the publickey of writekey
	require.Equal(wKey.PublicKey().Bytes(), id.WritePk().Bytes())

	// get the readKey for the address
	rKey := rwCap.ReadKey(addr)

	// make sure the verifier of id matches the publicKey of readKey
	require.Equal(rKey.PublicKey().Bytes(), id.ReadPk().Bytes())
	payload := []byte("hello world")

	// verify that writing with WriteKey() works
	err = c.Put(id, wKey.Sign(payload), payload)
	require.NoError(err)

	// verify that writing with wrong key fails:
	err = c.Put(id, rKey.Sign(payload), payload)
	require.Error(err)

	// verify that Reading with the ROKey interface works
	roKey := rwCap.ReadOnly().ReadKey(addr)
	payload2, err := c.Get(id, roKey.Sign(id.Bytes()))
	require.NoError(err)
	require.Equal(payload, payload2)

	payload2 = []byte("goodbye world")
	// verify that Writing with the WOKey works
	woKey := rwCap.WriteOnly().WriteKey(addr)
	id = rwCap.WriteOnly().Addr(addr)
	err = c.Put(id, woKey.Sign(payload2), payload2)
	require.NoError(err)
	resp, err := c.Get(id, roKey.Sign(id.Bytes()))
	require.NoError(err)
	require.Equal(payload2, resp)
}

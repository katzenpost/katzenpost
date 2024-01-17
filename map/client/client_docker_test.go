//go:build docker_test
// +build docker_test

// SPDX-FileCopyrightText: Copyright (C) 2021  Masala
// SPDX-License-Identifier: AGPL-3.0-only

package client

import (
	"context"
	"io"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/client"
	"github.com/katzenpost/katzenpost/client/config"
	"github.com/katzenpost/katzenpost/core/crypto/eddsa"
	"github.com/katzenpost/katzenpost/core/crypto/rand"
	"github.com/katzenpost/katzenpost/map/crypto"
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
	rwCap := crypto.NewReadWriteCapability(pk)

	// get the id and writeKey for an addrress
	addr := make([]byte, 32)
	_, err = io.ReadFull(rand.Reader, addr)
	require.NoError(err)
	id := rwCap.RootCapability.ForAddr(addr)
	wKey := rwCap.WriteCapForAddr(addr)

	// make sure that the verifier of id matches the publickey of writekey
	require.Equal(wKey.PublicKey().Bytes(), id.WritePk().Bytes())

	// get the readKey for the address
	rKey := rwCap.Read(addr)

	// make sure the verifier of id matches the publicKey of readKey
	require.Equal(rKey.PublicKey().Bytes(), id.ReadPk().Bytes())
	payload := []byte("hello world")

	// verify that writing with Write() works
	err = c.Put(id, wKey.Sign(payload), payload)
	require.NoError(err)

	// verify that writing with wrong key fails:
	err = c.Put(id, rKey.Sign(payload), payload)
	require.Error(err)

	// verify that Reading with the ROKey interface works
	roKey := rwCap.ReadOnly().Read(addr)
	payload2, err := c.Get(id, roKey.Sign(id.Bytes()))
	require.NoError(err)
	require.Equal(payload, payload2)

	payload2 = []byte("goodbye world")
	// verify that Writing with the WOKey works
	woKey := rwCap.WriteOnly().Write(addr)
	id = rwCap.WriteOnly().Addr(addr)
	err = c.Put(id, woKey.Sign(payload2), payload2)
	require.NoError(err)
	resp, err := c.Get(id, roKey.Sign(id.Bytes()))
	require.NoError(err)
	require.Equal(payload2, resp)
}

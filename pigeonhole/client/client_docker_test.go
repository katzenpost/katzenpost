// client_test.go - pigeonhole service client tests
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
	"time"

	"github.com/katzenpost/hpqc/rand"
	"github.com/katzenpost/hpqc/sign/ed25519"
	"github.com/katzenpost/katzenpost/client"
	"github.com/katzenpost/katzenpost/client/config"
	"github.com/katzenpost/katzenpost/pigeonhole/common"
	"github.com/stretchr/testify/require"
)

func TestCreatePigeonhole(t *testing.T) {
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
	pk, _, err := ed25519.NewKeypair(rand.Reader)
	require.NoError(err)
	rwCap := common.NewRWCap(pk)

	// get the id and writeKey for an addrress
	addr := make([]byte, 32)
	_, err = io.ReadFull(rand.Reader, addr)
	require.NoError(err)
	id := rwCap.Addr(addr)
	wKey := rwCap.WriteKey(addr)

	// make sure that the verifier of id matches the publickey of writekey
	require.Equal(wKey.PublicKey().Bytes(), id.WriteVerifier().Bytes())

	// get the readKey for the address
	rKey := rwCap.ReadKey(addr)

	// make sure the verifier of id matches the publicKey of readKey
	require.Equal(rKey.PublicKey().Bytes(), id.ReadVerifier().Bytes())
	payload := []byte("hello world")

	// verify that writing with WriteKey() works
	err = c.Put(id, wKey.Sign(payload), payload)
	require.NoError(err)

	// verify that writing with wrong key fails:
	badpayload := []byte("write fails")
	err = c.Put(id, rKey.Sign(badpayload), badpayload)
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
	// XXX: Put is not using a blocking method here, so we're racing Get
	<-time.After(10 * time.Second)
	resp, err := c.Get(id, roKey.Sign(id.Bytes()))
	require.NoError(err)
	require.Equal(payload2, resp)
}

func TestCreateDuplex(t *testing.T) {
	require := require.New(t)
	cfg, err := config.LoadFile("testdata/client.toml")
	require.NoError(err)

	kClient, err := client.New(cfg)
	require.NoError(err)

	ctx := context.Background()
	session, err := kClient.NewTOFUSession(ctx)
	require.NoError(err)
	session.WaitForDocument(ctx)

	pigeonholeClient, err := NewClient(session)
	require.NoError(err)
	require.NotNil(pigeonholeClient)

	a := DuplexFromSeed(pigeonholeClient, true, []byte("secret"))
	b := DuplexFromSeed(pigeonholeClient, false, []byte("secret"))

	ahello := []byte("hello from a")
	bhello := []byte("hello from b")
	addr := []byte("address")
	err = a.Put(addr, ahello)
	require.NoError(err)

	err = b.Put(addr, bhello)
	require.NoError(err)

	resp, err := b.Get(addr)
	require.NoError(err)
	require.Equal(resp, ahello)

	resp, err = a.Get(addr)
	require.NoError(err)
	require.Equal(resp, bhello)
}

func TestAsyncGetPigeonHole(t *testing.T) {
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

	// test retrieving and putting an item

	// create a capability key
	pk, _, err := ed25519.NewKeypair(rand.Reader)
	require.NoError(err)
	rwCap := common.NewRWCap(pk)

	// get the id and writeKey for an addrress
	addr := make([]byte, 32)
	payload := []byte("asynchronously respond to Get")
	_, err = io.ReadFull(rand.Reader, addr)
	require.NoError(err)
	id := rwCap.Addr(addr)
	wKey := rwCap.WriteKey(addr)
	rKey := rwCap.ReadKey(addr)
	senderErrCh := make(chan error, 0)
	receiverResultCh := make(chan interface{}, 0)

	sendAfter := 4 * time.Second
	timeout := 16 * time.Second
	go func() {
		// send the Put after the Get
		<-time.After(sendAfter)
		senderErrCh <- c.Put(id, wKey.Sign(payload), payload)
	}()

	go func() {
		t.Logf("Sending GetWithContext(), timeout in %v", timeout)
		ctx, cancelFn := context.WithTimeout(context.Background(), timeout)
		resp, err := c.GetWithContext(ctx, id, rKey.Sign(id.Bytes()))
		if err != nil {
			receiverResultCh <- err
		} else {
			receiverResultCh <- resp
		}
		cancelFn()
	}()

	e := <-senderErrCh
	require.NoError(e)
	r := <-receiverResultCh
	t.Logf("Got Response")
	switch r := r.(type) {
	case []byte:
		require.Equal(r, payload)
	case error:
		require.NoError(r)
	default:
		t.Logf("Got unexpected type: %T", r)
		t.FailNow()
	}
}

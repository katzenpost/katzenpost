// client_test.go - scratch service client tests
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
	"testing"
	"time"

	"github.com/katzenpost/hpqc/bacap"
	"github.com/katzenpost/hpqc/rand"
	"github.com/katzenpost/hpqc/sign/ed25519"
	"github.com/katzenpost/katzenpost/client"
	"github.com/katzenpost/katzenpost/client/config"
	"github.com/stretchr/testify/require"
)

func TestCreateScratch(t *testing.T) {
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

	// create a new owner capability
	root, err := bacap.NewBoxOwnerCap(rand.Reader)
	require.NoError(err)

	// derive the a read capability
	readCap := root.UniversalReadCap()

	// create a new index
	m, err := bacap.NewMessageBoxIndex(rand.Reader)
	require.NoError(err)

	payload := []byte("ciphertext goes here")

	// verify that signing and uploading works
	id, sig := m.SignBox(root, nil, payload)
	sig64 := new([ed25519.SignatureSize]byte)
	copy(sig64[:], sig)
	err = c.Put(nil, &id, payload, sig64)
	require.NoError(err)

	// verify that writing with bad signature fails:
	badsig := &[64]byte{}
	err = c.Put(nil, &id, payload, badsig)
	require.Error(err)

	// verify that reading works
	id2 := m.BoxIDForContext(readCap, nil)
	p := id2.ByteArray()
	payload2, _, err := c.Get(nil, &p)
	require.NoError(err)
	require.Equal(payload, payload2)
}

func TestAsyncGetScratch(t *testing.T) {
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

	// create a new owner capability
	root, err := bacap.NewBoxOwnerCap(rand.Reader)
	require.NoError(err)

	// derive the a read capability
	readCap := root.UniversalReadCap()

	// create a new index
	m, err := bacap.NewMessageBoxIndex(rand.Reader)
	require.NoError(err)

	payload := []byte("asynchronously respond to Get")
	id, sig := m.SignBox(root, nil, payload)

	senderErrCh := make(chan error, 0)
	receiverResultCh := make(chan interface{}, 0)

	sendAfter := 4 * time.Second
	timeout := 16 * time.Second
	go func() {
		// send the Put after the Get
		<-time.After(sendAfter)
		senderErrCh <- c.Put(id, payload, sig)
	}()

	go func() {
		t.Logf("Sending Get(), timeout in %d", timeout)
		ctx, cancelFn := context.WithTimeout(context.Background(), timeout)
		resp, _, err := c.Get(ctx, id)
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

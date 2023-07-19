// client_test.go - stream socket client tests
// Copyright (C) 2023  Masala
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
	"bufio"
	"bytes"
	"github.com/katzenpost/katzenpost/core/crypto/rand"
	"github.com/stretchr/testify/require"
	"io"
	"net"
	"net/http"
	_ "net/http/pprof"
	"net/url"
	"runtime"
	"sync"
	"testing"
)

var (
	cfgFile = "testdata/client.toml"
)

func TestDockerNewClient(t *testing.T) {
	require := require.New(t)
	session, err := GetSession(cfgFile)
	require.NoError(err)
	require.NotNil(session)
	c, err := NewClient(session)
	require.NoError(err)
	require.NotNil(c)
}

func TestDockerProxy(t *testing.T) {
	require := require.New(t)
	session, err := GetSession(cfgFile)
	require.NoError(err)
	require.NotNil(session)
	c, err := NewClient(session)
	require.NoError(err)
	require.NotNil(c)

	// make a unique id
	id := make([]byte, 32)
	_, err = io.ReadFull(rand.Reader, id)
	require.NoError(err)

	// add some credit
	err = <-c.Topup(id)
	require.NoError(err)

	// open a listening socket
	r, err := net.ListenTCP("tcp", &net.TCPAddr{})
	require.NoError(err)

	wg := new(sync.WaitGroup)
	wg.Add(1)

	payload := make([]byte, 4200000)
	_, err = io.ReadFull(rand.Reader, payload)
	require.NoError(err)

	proxiedpayload := make([]byte, 4200000)
	// wait for a connection from the proxy server
	go func() {
		incoming, err := r.Accept()
		t.Logf("Accept connection from server")
		n, err := io.ReadFull(incoming, proxiedpayload)
		require.Equal(n, len(proxiedpayload))
		t.Logf("Read payload from server")
		require.NoError(err)
		incoming.Close()
		wg.Done()
	}()

	// dial our socket with proxy
	u := new(url.URL)
	u, err = u.Parse("tcp://" + r.Addr().String())
	require.NoError(err)
	errCh := c.Dial(id, u) // Dial returns a channel that may send an error
	require.NoError(<-errCh)
	piper, pipew := net.Pipe()
	proxyConn, errCh := c.Proxy(id, pipew)
	_, err = io.Copy(piper, bufio.NewReader(bytes.NewReader(payload)))
	require.NoError(err)
	wg.Wait()
	proxyConn.Close()
	require.NoError(<-errCh)
	require.Equal(proxiedpayload, payload)
	require.NoError(err)
}

func init() {
	go func() {
		http.ListenAndServe("localhost:0", nil)
	}()
	runtime.SetMutexProfileFraction(1)
	runtime.SetBlockProfileRate(1)
}

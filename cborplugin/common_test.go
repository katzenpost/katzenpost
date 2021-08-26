// common_test.go - common tests for cbor plugin system
// Copyright (C) 2021  David Stainton.
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

package cborplugin

import (
	"io/ioutil"
	"path/filepath"
	"testing"

	"github.com/katzenpost/core/log"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
)

func TestCommandIOBasic(t *testing.T) {
	logBackend, err := log.New("", "DEBUG", false)
	require.NoError(t, err)
	clientLog := logBackend.GetLogger("client")
	serverLog := logBackend.GetLogger("server")

	client := NewCommandIO(clientLog)
	server := NewCommandIO(serverLog)

	dir, err := ioutil.TempDir("", "commandio_socket_test")
	require.NoError(t, err)
	socketFile := filepath.Join(dir, "socket")

	commandFactory := new(payloadFactory)

	g := new(errgroup.Group)
	g.Go(func() error {
		server.Start(false, socketFile, commandFactory)
		return nil
	})
	err = g.Wait()
	require.NoError(t, err)

	go client.Start(true, socketFile, commandFactory)
	server.Accept()
}

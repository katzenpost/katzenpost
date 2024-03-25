// socket_test.go - tests for cbor plugin system
// Copyright (C) 2023  Masala.
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
	"fmt"
	"github.com/katzenpost/katzenpost/core/log"
	"github.com/stretchr/testify/require"
	"os"
	"path/filepath"
	"testing"
)

// test instantiating a client and server socket and sending/receiving commands
// mock a plugin implementation

type MockPlugin struct {
	params *Parameters
}

func (m *MockPlugin) OnCommand(cmd Command) (Command, error) {
	switch cmd.(type) {
	case *ParametersRequest:
		return m.params, nil
	default:
		return nil, nil
	}
}

func (m *MockPlugin) RegisterConsumer(*Server) {
}

func TestCommandIOCommands(t *testing.T) {
	require := require.New(t)
	logBackend, err := log.New("", "DEBUG", false)
	if err != nil {
		panic(err)
	}
	serverLog := logBackend.GetLogger("cborplugin_server")

	// choose a temporary location for unix socket
	tmpDir, err := os.MkdirTemp("", "cborplugin")
	require.NoError(err)
	socketFile := filepath.Join(tmpDir, fmt.Sprintf("%d.cborplugin.socket", os.Getpid()))

	// create MockPlugin with some Parameters set
	mockPlugin := &MockPlugin{params: &Parameters{"testKey": "testValue"}}

	// instantiate CommandIO client and server
	cborServer := NewServer(serverLog, socketFile, mockPlugin)
	cborClient := NewClient(logBackend, "test", "test")

	// don't start the client with Start(), because there isn't a plugin commnad to exec,
	// instead, set the socketFile manually and start the CommandIO worker and Accept the connection
	cborClient.socketFile = socketFile
	cborClient.socket.Start(true, cborClient.socketFile)
	cborServer.Accept()

	// send a GetParameters command and verify that the response contains the correct values
	params, err := cborClient.GetParameters()
	require.NoError(err)

	for k, v := range *(mockPlugin.params) {
		require.Contains(*params, k)
		require.Equal((*params)[k], v)
	}
}

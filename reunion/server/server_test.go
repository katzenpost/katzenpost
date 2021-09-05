// server_test.go - Reunion server tests.
// Copyright (C) 2019  David Stainton.
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

package server

import (
	"io/ioutil"
	"testing"

	"github.com/katzenpost/katzenpost/reunion/commands"
	"github.com/katzenpost/katzenpost/reunion/epochtime/katzenpost"
	"github.com/stretchr/testify/require"
)

func TestServer(t *testing.T) {
	require := require.New(t)

	clock := new(katzenpost.Clock)
	epoch, _, _ := clock.Now()
	stateFile, err := ioutil.TempFile("", "catshadow_test_statefile")
	require.NoError(err)
	stateFile.Close()

	logPath := ""
	logLevel := "DEBUG"
	server, err := NewServer(clock, stateFile.Name(), logPath, logLevel)
	require.NoError(err)

	sendt1 := commands.SendT1{
		Epoch:   epoch,
		Payload: []byte{0xDE, 0xAD, 0xBE, 0xEF},
	}
	_, err = server.ProcessQuery(&sendt1)
	require.NoError(err)

	// XXX ...
}

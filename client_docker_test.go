// client.go - client
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

// +build docker_test

package catshadow

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/katzenpost/catshadow/config"
	"github.com/katzenpost/client"
	"github.com/stretchr/testify/require"
)

func TestCatshadowBasics(t *testing.T) {
	require := require.New(t)

	// Load catshadow config file.
	catshadowCfg, err := config.LoadFile("testdata/catshadow.toml")
	require.NoError(err)
	var stateWorker *StateWriter
	var catShadowClient *Client
	cfg, err := catshadowCfg.ClientConfig()
	require.NoError(err)

	tmpDir, err := ioutil.TempDir("", "catshadow_test")
	require.NoError(err)
	stateFile := filepath.Join(tmpDir, fmt.Sprintf("%d.catshadow.state", os.Getpid()))
	if _, err := os.Stat(stateFile); !os.IsNotExist(err) {
		panic(err)
	}
	cfg, linkKey := client.AutoRegisterRandomClient(cfg)
	c, err := client.New(cfg)
	require.NoError(err)
	passphrase := []byte("")
	stateWorker, err = NewStateWriter(c.GetLogger("catshadow_state"), stateFile, passphrase)
	require.NoError(err)
	backendLog, err := catshadowCfg.InitLogBackend()
	require.NoError(err)

	user := fmt.Sprintf("%x", linkKey.PublicKey().Bytes())
	catShadowClient, err = NewClientAndRemoteSpool(backendLog, c, stateWorker, user, linkKey)
	require.NoError(err)

	// Start catshadow client.
	stateWorker.Start()
	catShadowClient.Start()

	// XXX blah blah blah test stuff here.

	catShadowClient.Shutdown()
}

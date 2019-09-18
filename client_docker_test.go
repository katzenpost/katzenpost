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
	"time"

	"github.com/katzenpost/catshadow/config"
	"github.com/katzenpost/client"
	"github.com/katzenpost/core/crypto/rand"
	"github.com/stretchr/testify/require"
)

func createCatshadowClient(t *testing.T) *Client {
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

	id := [6]byte{}
	_, err = rand.Reader.Read(id[:])
	require.NoError(err)
	stateFile := filepath.Join(tmpDir, fmt.Sprintf("%x.catshadow.state", id))
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

	return catShadowClient
}

func TestCatshadowBasics(t *testing.T) {
	//require := require.New(t)

	alice := createCatshadowClient(t)
	bob := createCatshadowClient(t)

	sharedSecret := []byte("twas brillig and slithy toves6e")
	alice.NewContact("bob", sharedSecret)
	bob.NewContact("alice", sharedSecret)

	aliceEventsCh := alice.EventsChan()
	ev := <-aliceEventsCh
	_, ok := ev.(KeyExchangeCompleted)
	if !ok {
		panic("wtf")
	}

	bobEventsCh := bob.EventsChan()
	ev = <-bobEventsCh
	_, ok = ev.(KeyExchangeCompleted)
	if !ok {
		panic("wtf")
	}

	/*
		alice.SendMessage("bob", []byte("hello bobby, this is a message"))
		ev = <-aliceEventsCh
		_, ok = ev.(MessageDelivered)
		if !ok {
			panic("wtf")
		}


		ev = <-bobEventsCh
		_, ok = ev.(MessageReceived)
		if !ok {
			panic("wtf")
		}
	*/

	time.Sleep(3 * time.Second)
	alice.Shutdown()
	bob.Shutdown()
}

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
	//cfg.Logging.Level = "INFO" // client verbosity reductionism
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

func TestDockerPandaSuccess(t *testing.T) {
	require := require.New(t)

	alice := createCatshadowClient(t)
	bob := createCatshadowClient(t)

	sharedSecret := []byte("There is a certain kind of small town that grows like a boil on the ass of every Army base in the world.")
	randBytes := [8]byte{}
	_, err := rand.Reader.Read(randBytes[:])
	require.NoError(err)
	sharedSecret = append(sharedSecret, randBytes[:]...)

	alice.NewContact("bob", sharedSecret)
	bob.NewContact("alice", sharedSecret)

	aliceEventsCh := alice.EventSink
	ev := <-aliceEventsCh
	keyExchangeCompletedEvent, ok := ev.(*KeyExchangeCompletedEvent)
	require.True(ok)
	require.Nil(keyExchangeCompletedEvent.Err)

	bobEventsCh := bob.EventSink
	ev = <-bobEventsCh
	keyExchangeCompletedEvent, ok = ev.(*KeyExchangeCompletedEvent)
	require.True(ok)
	require.Nil(keyExchangeCompletedEvent.Err)

	alice.Shutdown()
	bob.Shutdown()
}

func TestDockerPandaTagContendedError(t *testing.T) {
	require := require.New(t)

	alice := createCatshadowClient(t)
	bob := createCatshadowClient(t)

	sharedSecret := []byte("twas brillig and the slithy toves")
	randBytes := [8]byte{}
	_, err := rand.Reader.Read(randBytes[:])
	require.NoError(err)
	sharedSecret = append(sharedSecret, randBytes[:]...)

	alice.NewContact("bob", sharedSecret)
	bob.NewContact("alice", sharedSecret)

	aliceEventsCh := alice.EventSink
loop1:
	for {
		ev := <-aliceEventsCh
		switch event := ev.(type) {
		case *KeyExchangeCompletedEvent:
			require.Nil(event.Err)
			break loop1
		default:
		}
	}

	bobEventsCh := bob.EventSink
loop2:
	for {
		ev := <-bobEventsCh
		switch event := ev.(type) {
		case *KeyExchangeCompletedEvent:
			require.Nil(event.Err)
			break loop2
		default:
		}
	}

	alice.Shutdown()
	bob.Shutdown()

	// second phase of test, use same panda shared secret
	// in order to test that it invokes a tag contended error
	ada := createCatshadowClient(t)
	jeff := createCatshadowClient(t)

	ada.NewContact("jeff", sharedSecret)
	jeff.NewContact("ada", sharedSecret)

loop3:
	for {
		ev := <-ada.EventSink
		switch event := ev.(type) {
		case *KeyExchangeCompletedEvent:
			require.NotNil(event.Err)
			break loop3
		default:
		}
	}

loop4:
	for {
		ev := <-jeff.EventSink
		switch event := ev.(type) {
		case *KeyExchangeCompletedEvent:
			require.NotNil(event.Err)
			break loop4
		default:
		}
	}

	ada.Shutdown()
	jeff.Shutdown()
}

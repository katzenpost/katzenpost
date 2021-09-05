// SPDX-FileCopyrightText: 2021, Masala <masala@riseup.net>
// SPDX-License-Identifier: AGPL-3.0-or-later
//
// client_test.go - client tests that do not require docker or network connectivity
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

package catshadow

import (
	"fmt"
	cConfig "github.com/katzenpost/client/config"
	"github.com/katzenpost/core/crypto/ecdh"
	"io/ioutil"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/katzenpost/catshadow/config"
	"github.com/katzenpost/client"
	"github.com/katzenpost/core/crypto/rand"
	"github.com/stretchr/testify/require"
)

func createRandomStateFile(t *testing.T) string {
	require := require.New(t)

	tmpDir, err := ioutil.TempDir("", "catshadow_test")
	require.NoError(err)
	id := [6]byte{}
	_, err = rand.Reader.Read(id[:])
	require.NoError(err)
	stateFile := filepath.Join(tmpDir, fmt.Sprintf("%x.catshadow.state", id))
	_, err = os.Stat(stateFile)
	require.True(os.IsNotExist(err))
	return stateFile
}

func TestBlobStorage(t *testing.T) {
	require := require.New(t)
	linkKey, err := ecdh.NewKeypair(rand.Reader)
	require.NoError(err)

	state := &State{
		Blob:          make(map[string][]byte),
		Contacts:      make([]*Contact, 0),
		Conversations: make(map[string]map[MessageID]*Message),
		User:          "foo",
		Provider:      "bar",
		LinkKey:       linkKey,
	}

	aliceState := createRandomStateFile(t)
	passphrase := []byte("")
	catshadowCfg, err := config.LoadFile("testdata/catshadow.toml")
	require.NoError(err)
	cfg, err := catshadowCfg.ClientConfig()
	require.NoError(err)
	cfg.Account = &cConfig.Account{
		User:     state.User,
		Provider: state.Provider,
	}

	c, err := client.New(cfg)
	require.NoError(err)
	stateWorker, err := NewStateWriter(c.GetLogger("catshadow_state"), aliceState, passphrase)
	require.NoError(err)
	stateWorker.Start()
	logBackend, err := catshadowCfg.InitLogBackend()
	require.NoError(err)
	cs := &Client{blob: make(map[string][]byte),
		logBackend:         logBackend,
		client:             c,
		log:                logBackend.GetLogger("foo"),
		contacts:           make(map[uint64]*Contact),
		conversationsMutex: new(sync.Mutex),
		blobMutex:          new(sync.Mutex),
		stateWorker:        stateWorker,
	}
	require.NoError(err)
	cs.AddBlob("foo", []byte{1, 2, 3})
	b, err := cs.GetBlob("foo")
	require.NoError(err)
	require.Equal(b, []byte{1, 2, 3})
	err = cs.DeleteBlob("foo")
	require.NoError(err)
	_, err = cs.GetBlob("foo")
	require.Error(err, errBlobNotFound)
	stateWorker.Halt()
}

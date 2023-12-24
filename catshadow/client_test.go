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
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/katzenpost/katzenpost/client2"
	"github.com/katzenpost/katzenpost/client2/config"
	"github.com/katzenpost/katzenpost/core/crypto/rand"
	"github.com/katzenpost/katzenpost/core/log"
	"github.com/stretchr/testify/require"
)

func createRandomStateFile(t *testing.T) string {
	require := require.New(t)

	tmpDir, err := os.MkdirTemp("", "catshadow_test")
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
	t.Parallel()

	cfg, err := config.LoadFile("testdata/catshadow.toml")
	require.NoError(t, err)

	egressSize := 100
	d, err := client2.NewDaemon(cfg, egressSize)
	require.NoError(t, err)
	err = d.Start()
	require.NoError(t, err)

	// maybe we need to sleep first to ensure the daemon is listening first before dialing
	//time.Sleep(time.Second * 3)

	aliceState := createRandomStateFile(t)
	passphrase := []byte("")

	c := client2.NewThinClient(cfg)
	err = c.Dial()
	require.NoError(t, err)

	stateWorker, err := NewStateWriter(c.GetLogger("catshadow_state"), aliceState, passphrase)
	require.NoError(t, err)

	stateWorker.Start()
	logBackend, err := log.New(cfg.Logging.File, cfg.Logging.Level, cfg.Logging.Disable)
	require.NoError(t, err)

	cs := &Client{blob: make(map[string][]byte),
		logBackend:         logBackend,
		session:            c,
		log:                logBackend.GetLogger("foo"),
		contacts:           make(map[uint64]*Contact),
		conversationsMutex: new(sync.Mutex),
		blobMutex:          new(sync.Mutex),
		stateWorker:        stateWorker,
	}
	require.NoError(t, err)

	cs.AddBlob("foo", []byte{1, 2, 3})
	b, err := cs.GetBlob("foo")
	require.NoError(t, err)
	require.Equal(t, b, []byte{1, 2, 3})

	err = cs.DeleteBlob("foo")
	require.NoError(t, err)

	_, err = cs.GetBlob("foo")
	require.Error(t, err, ErrBlobNotFound)
	stateWorker.Halt()
}

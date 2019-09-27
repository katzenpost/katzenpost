// client_test.go - memspool client tests
// Copyright (C) 2019  Masala.
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

package client

import (
	"bytes"
	"testing"
	"time"

	"github.com/katzenpost/client"
	"github.com/katzenpost/kimchi"
	"github.com/katzenpost/memspool/common"
	"github.com/stretchr/testify/require"
)

// TestNewUnreliableSpoolService tests creating a new spool service
func TestNewUnreliableSpoolService(t *testing.T) {
	require := require.New(t)
	k := kimchi.NewKimchi(33333, "", nil, false, 0, 2, 6)
	k.Run()

	go func() {
		defer k.Shutdown()
		cfg, username, linkKey, err := k.GetClientConfig()
		require.NoError(err)
		<-time.After(90 * time.Second) // must wait for provider to fetch pki document

		// instantiate a client instance
		c, err := client.New(cfg)
		require.NoError(err)
		t.Logf("Creating client")

		// add client log output
		go k.LogTailer(username, cfg.Logging.File)

		// instantiate a session
		s, err := c.NewSession(linkKey)
		require.NoError(err)
		t.Logf("Instantiating session")

		// look up a spool provider
		desc, err := s.GetService(common.SpoolServiceName)
		require.NoError(err)
		t.Logf("Found spool provider: %v@%v", desc.Name, desc.Provider)

		// create the spool on the remote provider
		spoolReadDescriptor, err := NewSpoolReadDescriptor(desc.Name, desc.Provider, s)
		require.NoError(err)

		// append to a spool
		message := []byte("hello there")
		appendCmd, err := common.AppendToSpool(spoolReadDescriptor.ID, message)
		require.NoError(err)
		rawResponse, err := s.BlockingSendUnreliableMessage(desc.Name, desc.Provider, appendCmd)
		require.NoError(err)
		response, err := common.SpoolResponseFromBytes(rawResponse)
		require.NoError(err)
		require.True(response.IsOK())

		messageID := uint32(1) // where do we learn messageID?

		// read from a spool (should find our original message)
		readCmd, err := common.ReadFromSpool(spoolReadDescriptor.ID, messageID, spoolReadDescriptor.PrivateKey)
		require.NoError(err)
		rawResponse, err = s.BlockingSendUnreliableMessage(desc.Name, desc.Provider, readCmd)
		require.NoError(err)
		response, err = common.SpoolResponseFromBytes(rawResponse)
		require.NoError(err)
		require.True(response.IsOK())
		// XXX require.Equal(response.SpoolID, spoolReadDescriptor.ID)
		require.True(bytes.Equal(response.Message, message))

		// purge a spool
		purgeCmd, err := common.PurgeSpool(spoolReadDescriptor.ID, spoolReadDescriptor.PrivateKey)
		require.NoError(err)
		rawResponse, err = s.BlockingSendUnreliableMessage(desc.Name, desc.Provider, purgeCmd)
		require.NoError(err)
		response, err = common.SpoolResponseFromBytes(rawResponse)
		require.NoError(err)
		require.True(response.IsOK())

		// read from a spool (should be empty?)
		readCmd, err = common.ReadFromSpool(spoolReadDescriptor.ID, messageID, spoolReadDescriptor.PrivateKey)
		require.NoError(err)
		rawResponse, err = s.BlockingSendUnreliableMessage(desc.Name, desc.Provider, readCmd)
		response, err = common.SpoolResponseFromBytes(rawResponse)
		require.NoError(err)
		require.False(response.IsOK())
	}()
	k.Wait()
	t.Logf("Terminated")
}

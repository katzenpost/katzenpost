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
	"github.com/katzenpost/core/crypto/eddsa"
	"github.com/katzenpost/core/crypto/rand"
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

		// create a spool key
		spoolPrivateKey, err := eddsa.NewKeypair(rand.Reader)
		require.NoError(err)

		// look up a spool provider
		desc, err := s.GetService(common.SpoolServiceName)
		require.NoError(err)
		t.Logf("Found spool provider: %v@%v", desc.Name, desc.Provider)

		// create the spool on the remote provider
		spoolId, err := svc.CreateSpool(spoolPrivateKey, desc.Name, desc.Provider)
		require.NoError(err)
		t.Logf("Created spool %x", spoolId)

		// append to a spool
		message := []byte("hello there")
		err = svc.AppendToSpool(spoolId, message, desc.Name, desc.Provider)
		require.NoError(err)
		t.Logf("Appending message %s to spool %x on %v@%v", message, spoolId, desc.Name, desc.Provider)

		messageID := uint32(1) // where do we learn messageID?

		// read from a spool (should find our original message)
		resp, err := svc.ReadFromSpool(spoolId, messageID, spoolPrivateKey, desc.Name, desc.Provider)
		require.NoError(err)
		t.Logf("Got message %s from spool %x with status %s", resp.Message, resp.SpoolID, resp.Status)
		if !bytes.Equal(resp.SpoolID, spoolId) {
			t.Logf("spool response returned status %s", resp.Status)
			t.Errorf("spool ID's differ in response!?: %x vs %x", resp.SpoolID, spoolId)
		}
		require.True(bytes.Equal(resp.Message, message))
		require.True(resp.Status == "OK")
		require.True(len(resp.Padding) == 120)

		// purge a spool
		err = svc.PurgeSpool(spoolId, spoolPrivateKey, desc.Name, desc.Provider)
		require.NoError(err)

		// read from a spool (should be empty?)
		resp, err = svc.ReadFromSpool(spoolId, messageID, spoolPrivateKey, desc.Name, desc.Provider)
		require.Error(err)
	}()
	k.Wait()
	t.Logf("Terminated")
}

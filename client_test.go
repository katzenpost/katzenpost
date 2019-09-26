// client_test.go - Katzenpost client library tests.
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

// Package client provides a Katzenpost client library.
package client

import (
	"sync"
	"testing"
	"time"

	"github.com/katzenpost/kimchi"
	"github.com/stretchr/testify/require"
)

const basePort = 30000

// TestClientConnect tests that a client can connect and send a message to the loop service
func TestClientConnect(t *testing.T) {
	require := require.New(t)
	voting := false
	nVoting := 0
	nProvider := 2
	nMix := 6
	k := kimchi.NewKimchi(basePort+400, "", nil, voting, nVoting, nProvider, nMix)
	t.Logf("Running TestClientConnect.")
	k.Run()

	go func() {
		defer k.Shutdown()

		// create a client configuration
		cfg, username, linkKey, err := k.GetClientConfig()
		require.NoError(err)
		require.NotNil(cfg)

		<-time.After(90 * time.Second) // must wait for provider to fetch pki document
		t.Logf("Time is up!")

		// instantiate a client instance
		c, err := New(cfg)
		require.NotNil(cfg)
		require.NoError(err)

		// add client log output
		go k.LogTailer(username, cfg.Logging.File)

		// instantiate a session
		s, err := c.NewSession(linkKey)
		require.NoError(err)

		// look up a well known service
		desc, err := s.GetService("loop")
		require.NoError(err)

		// send a message
		t.Logf("desc.Provider: %s", desc.Provider)
		_, err = s.BlockingSendUnreliableMessage(desc.Name, desc.Provider, []byte("hello!"))
		require.NoError(err)
		t.Logf("Sent unreliable message to loop service")

		c.Shutdown()
		t.Logf("Shutdown requested")
		c.Wait()
	}()

	k.Wait()
	t.Logf("Terminated.")
}

// TestAutoRegisterRandomClient tests client registration
func TestAutoRegisterRandomClient(t *testing.T) {
	require := require.New(t)
	voting := false
	nVoting := 0
	nProvider := 2
	nMix := 6
	k := kimchi.NewKimchi(basePort+500, "", nil, voting, nVoting, nProvider, nMix)
	t.Logf("Running TestAutoRegisterRandomClient.")
	k.Run()

	go func() {
		defer k.Shutdown()
		<-time.After(90 * time.Second) // must wait for provider to fetch pki document
		cfg, err := k.GetClientNetconfig()
		require.NoError(err)

		_, linkKey := AutoRegisterRandomClient(cfg)
		require.NotNil(linkKey)

		// Verify that the client can connect
		c, err := New(cfg)
		require.NoError(err)

		// instantiate a session
		s, err := c.NewSession(linkKey)
		require.NoError(err)

		// look up a well known service
		desc, err := s.GetService("loop")
		require.NoError(err)
		t.Logf("Found %v kaetzchen on %v", desc.Name, desc.Provider)

		c.Shutdown()
		t.Logf("Shutdown requested")
		c.Wait()
	}()
	k.Wait()
}

// TestDecoyClient tests client with Decoy traffic enabled
func TestDecoyClient(t *testing.T) {
	require := require.New(t)
	voting := false
	nVoting := 0
	nProvider := 2
	nMix := 6
	k := kimchi.NewKimchi(basePort+500, "", nil, voting, nVoting, nProvider, nMix)
	t.Logf("Running TestAutoRegisterRandomClient.")
	k.Run()

	go func() {
		defer k.Shutdown()
		<-time.After(90 * time.Second) // must wait for provider to fetch pki document
		cfg, err := k.GetClientNetconfig()
		require.NoError(err)
		cfg.Debug.DisableDecoyTraffic = false

		_, linkKey := AutoRegisterRandomClient(cfg)
		require.NotNil(linkKey)

		// Verify that the client can connect
		c, err := New(cfg)
		require.NoError(err)

		// instantiate a session
		s, err := c.NewSession(linkKey)
		require.NoError(err)

		// look up a well known service
		desc, err := s.GetService("loop")
		require.NoError(err)
		t.Logf("Found %v kaetzchen on %v", desc.Name, desc.Provider)

		wg := &sync.WaitGroup{}
		for i := 0; i < 3; i++ {
			wg.Add(1)
			go func() {
				t.Logf("SendUnreliableMessage()")
				_, err := s.BlockingSendUnreliableMessage(desc.Name, desc.Provider, []byte("hello!"))
				require.NoError(err)
				wg.Done()
			}()
		}
		wg.Wait()

		c.Shutdown()
		t.Logf("Shutdown requested")
		c.Wait()
	}()
	k.Wait()
}

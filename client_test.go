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
	"testing"
	"time"

	"github.com/katzenpost/core/epochtime"
	"github.com/katzenpost/kimchi"
	"github.com/stretchr/testify/assert"
)

const basePort = 30000

// TestClientConnect tests that a client can connect and send a message to the loop service
func TestClientConnect(t *testing.T) {
	t.Parallel()
	assert := assert.New(t)
	voting := true
	nVoting := 3
	nProvider := 2
	nMix := 6
	k := kimchi.NewKimchi(basePort+400, "", nil, voting, nVoting, nProvider, nMix)
	t.Logf("Running TestClientConnect.")
	k.Run()

	go func() {
		defer k.Shutdown()
		_, _, till := epochtime.Now()
		till += epochtime.Period // wait for one vote round, aligned at start of epoch
		<-time.After(till)
		t.Logf("Time is up!")

		// create a client configuration
		cfg, username, linkKey, err := k.GetClientConfig()
		assert.NoError(err)

		// instantiate a client instance
		c, err := New(cfg)
		assert.NoError(err)

		// add client log output
		go k.LogTailer(username, cfg.Logging.File)

		// instantiate a session
		s, err := c.NewSession(username, linkKey)
		assert.NoError(err)

		// get a PKI document? needs client method...
		desc, err := s.GetService("loop") // XXX: returns nil and no error?!
		assert.NoError(err)

		// send a message
		t.Logf("desc.Provider: %s", desc.Provider)
		_, err = s.SendUnreliableMessage(desc.Name, desc.Provider, []byte("hello!"))
		assert.NoError(err)

		c.Shutdown()
		c.Wait()
	}()

	k.Wait()
	t.Logf("Terminated.")
}

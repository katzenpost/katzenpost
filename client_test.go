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
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/katzenpost/core/epochtime"
	"github.com/katzenpost/kimchi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
		cfg, err := k.GetClientConfig()
		assert.NoError(err)

		// instantiate a client instance
		c, err := New(cfg)
		assert.NoError(err)

		// add client log output
		go k.LogTailer(cfg.Account.User, filepath.Join(cfg.Proxy.DataDir, cfg.Logging.File))

		// instantiate a session
		s, err := c.NewSession()
		assert.NoError(err)

		// get a PKI document? needs client method...
		desc, err := s.GetService("loop") // XXX: returns nil and no error?!
		assert.NoError(err)

		// send a message
		t.Logf("desc.Provider: %s", desc.Provider)
		id, err := s.SendUnreliableMessage(desc.Name, desc.Provider, []byte("hello!"))
		assert.NoError(err)

		_, err = s.WaitForReply(id)
		c.Shutdown()
		c.Wait()
	}()

	k.Wait()
	t.Logf("Terminated.")
}

// TestReliableDelivery verifies that all messages sent were delivered
func NoTestReliableDelivery(t *testing.T) {
	t.Parallel()
	t.Skip("Disabled until client library supports reliable delivery")
	assert := assert.New(t)
	require := require.New(t)
	voting := true
	nVoting := 3
	nProvider := 2
	nMix := 6
	p := &kimchi.Parameters{}
	p.Mu, p.LambdaP, p.LambdaL = 0.005, 0.005, 0.005
	k := kimchi.NewKimchi(basePort+700, "", p, voting, nVoting, nProvider, nMix)
	t.Logf("Running TestClientConnect.")
	k.Run()

	go func() {
		defer k.Shutdown()
		_, _, till := epochtime.Now()
		till += epochtime.Period // wait for one vote round, aligned at start of epoch
		<-time.After(till)
		t.Logf("Time is up!")

		// create a client configuration
		cfg, err := k.GetClientConfig()
		assert.NoError(err)

		// instantiate a client instance
		c, err := New(cfg)
		assert.NoError(err)

		// add client log output
		go k.LogTailer(cfg.Account.User, filepath.Join(cfg.Proxy.DataDir, cfg.Logging.File))

		// instantiate a session
		s, err := c.NewSession()
		require.NoError(err)
		require.NotNil(s)

		// get a PKI document? needs client method...
		desc, err := s.GetService("loop") // XXX: returns nil and no error?!
		require.NoError(err)

		// send a message
		t.Logf("desc.Provider: %s", desc.Provider)

		/* // SendMessage not available in client yet
		for i := 0; i < 10; i++ {
			msgid, err := s.SendMessage(desc.Name, desc.Provider, []byte("hello!"), true, true)
			require.NoError(err)

			// wait until timeout or a reply is received
			ch := make(chan []byte)
			go func() {
				ch <- s.WaitForReply(msgid)
			}()
			select {
			case <-time.After(30 * time.Second):
				assert.Fail("Timed out, no reply received")
			case r := <-ch:
				t.Logf("Got reply: %s", r)
			}
			close(ch)
		}
		*/
		c.Shutdown()
		c.Wait()
	}()

	k.Wait()
	t.Logf("Terminated.")
}

// TestMultipleClients tests concurrent client sessions on a provider
func NoTestMultipleClients(t *testing.T) {
	t.Parallel()
	t.Skip("Disabled until client library supports reliable delivery")
	//assert := assert.New(t)
	require := require.New(t)
	voting := true
	nVoting := 3
	nProvider := 2
	nMix := 6
	p := &kimchi.Parameters{}
	p.Mu, p.LambdaP, p.LambdaL = 0.005, 0.005, 0.005
	k := kimchi.NewKimchi(basePort+800, "", p, voting, nVoting, nProvider, nMix)
	t.Logf("Running TestClientConnect.")
	k.Run()

	go func() {
		defer k.Shutdown()
		_, _, till := epochtime.Now()
		till += epochtime.Period // wait for one vote round, aligned at start of epoch
		<-time.After(till)
		t.Logf("Time is up!")

		wg := new(sync.WaitGroup)
		for i := 0; i < 10; i++ {
			go func() {
				wg.Add(1)
				// create a client configuration
				cfg, err := k.GetClientConfig()
				require.NoError(err)

				// instantiate a client instance
				c, err := New(cfg)
				require.NoError(err)

				// add client log output
				go k.LogTailer(cfg.Account.User, filepath.Join(cfg.Proxy.DataDir, cfg.Logging.File))

				// instantiate a session
				s, err := c.NewSession()
				require.NoError(err)
				require.NotNil(s)

				// get a PKI document? needs client method...
				desc, err := s.GetService("loop") // XXX: returns nil and no error?!
				require.NoError(err)

				// send a message
				t.Logf("desc.Provider: %s", desc.Provider)

				/* // disabled until client supports Sendmessage
				for i := 0; i < 100; i++ {
					msgid, err := s.SendMessage(desc.Name, desc.Provider, []byte("hello!"), true, true)
					require.NoError(err)

					// wait until timeout or a reply is received
					ch := make(chan []byte)
					die := make(chan bool)
					go func() {
						select {
						case ch <- s.WaitForReply(msgid):
						case <- die:
						}
					}()
					select {
					case <-time.After(30 * time.Second):
						assert.Fail("Timed out, no reply received")
						die<-true
					case r := <-ch:
						t.Logf("Got reply: %s", r)
					}
					close(ch)
					close(die)
				}
				*/
				c.Shutdown()
				c.Wait()
				wg.Done()
			}()
		}
		wg.Wait()
	}()

	k.Wait()
	t.Logf("Terminated.")
}

// TestClientReceiveMessage tests that a client can send a message to self
func NoTestClientReceiveMessage(t *testing.T) {
	t.Parallel()
	assert := assert.New(t)
	voting := true
	nVoting := 3
	nProvider := 2
	nMix := 3
	k := kimchi.NewKimchi(basePort+500, "", nil, voting, nVoting, nProvider, nMix)
	t.Logf("Running TestClientConnect.")
	k.Run()

	go func() {
		defer k.Shutdown()
		_, _, till := epochtime.Now()
		// XXX; there seems to be a bug w/ messages getting dropped @ epoch transition
		till += epochtime.Period + 10*time.Second // wait for one vote round, aligned at start of epoch + slop
		<-time.After(till)
		t.Logf("Time is up!")

		// create a client configuration
		cfg, err := k.GetClientConfig()
		assert.NoError(err)

		// instantiate a client instance
		c, err := New(cfg)
		assert.NoError(err)
		assert.NotNil(c)

		// add client log output
		go k.LogTailer(cfg.Account.User, filepath.Join(cfg.Proxy.DataDir, cfg.Logging.File))

		// instantiate a session
		s, err := c.NewSession()
		assert.NoError(err)

		// send a message
		surb, err := s.SendUnreliableMessage(cfg.Account.User, cfg.Account.Provider, []byte("hello!"))
		assert.NoError(err)

		// wait until timeout or a reply is received
		ch := make(chan []byte)
		go func() {
			reply, err := s.WaitForReply(surb)
			if err != nil {
				panic(err)
			}
			ch <- reply
		}()
		select {
		case <-time.After(epochtime.Period):
			assert.Fail("Timed out, no reply received")
		case r := <-ch:
			t.Logf("Got reply: %s", r)
		}
		close(ch)
		c.Shutdown()
		c.Wait()
	}()
	k.Wait()
	t.Logf("Terminated.")
}

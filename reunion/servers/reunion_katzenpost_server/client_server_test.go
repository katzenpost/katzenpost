// client_server_test.go - Docker integration tests for client and server.
// Copyright (C) 2020  David Stainton.
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

//go:build docker_test
// +build docker_test

package main

import (
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/katzenpost/katzenpost/client"
	"github.com/katzenpost/katzenpost/client/config"
	"github.com/katzenpost/katzenpost/core/log"
	reunionClient "github.com/katzenpost/katzenpost/reunion/client"
	catClock "github.com/katzenpost/katzenpost/reunion/epochtime/katzenpost"
	"github.com/katzenpost/katzenpost/reunion/transports/katzenpost"
	"github.com/stretchr/testify/require"
)

const (
	initialPKIConsensusTimeout = 45 * time.Second
)

func TestDockerClientExchange1(t *testing.T) {
	require := require.New(t)

	cfg, err := config.LoadFile("testdata/catshadow.toml")
	require.NoError(err)
	c, err := client.New(cfg)
	require.NoError(err)
	session, err := c.NewTOFUSession()
	require.NoError(err)
	session.WaitForDocument()
	serviceDesc, err := session.GetService("reunion")
	require.NoError(err)

	transport := &katzenpost.Transport{
		Session:   session,
		Recipient: serviceDesc.Name,
		Provider:  serviceDesc.Provider,
	}
	clock := new(catClock.Clock)
	epoch, _, _ := clock.Now()
	srv := []byte{1, 2, 3}
	passphrase := []byte("blah blah motorcycle pencil sharpening gas tank")

	f := ""
	level := "DEBUG"
	disable := false
	logBackend, err := log.New(f, level, disable)
	require.NoError(err)

	var bobResult []byte
	var aliceResult []byte

	// client Alice

	alicePayload := []byte("Hello Bobby, what's up dude?")
	aliceContactID := uint64(1)
	aliceExchangelog := logBackend.GetLogger("alice_exchange")

	var wg sync.WaitGroup
	wg.Add(1)
	aliceUpdateCh := make(chan reunionClient.ReunionUpdate)
	shutdownCh := make(chan struct{})
	go func() {
		for {
			update := <-aliceUpdateCh
			if len(update.Result) > 0 {
				aliceResult = update.Result
				fmt.Printf("\n Alice got result: %s\n\n", update.Result)
				wg.Done()
			}
		}
	}()

	aliceExchange, err := reunionClient.NewExchange(alicePayload, aliceExchangelog, transport, aliceContactID, passphrase, srv, epoch, aliceUpdateCh, shutdownCh)
	require.NoError(err)

	// bob client
	bobPayload := []byte("yo Alice, so you are a cryptographer and a language designer both?")
	bobContactID := uint64(2)
	bobLogBackend, err := log.New(f, level, disable)
	require.NoError(err)
	bobExchangelog := bobLogBackend.GetLogger("bob_exchange")

	wg.Add(1)
	bobUpdateCh := make(chan reunionClient.ReunionUpdate)
	go func() {
		for {
			update := <-bobUpdateCh
			if len(update.Result) > 0 {
				bobResult = update.Result
				fmt.Printf("\n Bob got result: %s\n\n", update.Result)
				wg.Done()
			}
		}
	}()

	bobExchange, err := reunionClient.NewExchange(bobPayload, bobExchangelog, transport, bobContactID, passphrase, srv, epoch, bobUpdateCh, shutdownCh)
	require.NoError(err)

	// Run reunion client exchanges.

	go aliceExchange.Run()
	go bobExchange.Run()

	wg.Wait()

	require.Equal(aliceResult, bobPayload)
	require.Equal(bobResult, alicePayload)
}

func TestDockerClientExchange2(t *testing.T) {
	require := require.New(t)

	cfg, err := config.LoadFile("testdata/catshadow.toml")
	require.NoError(err)

	c, err := client.New(cfg)
	require.NoError(err)
	session, err := c.NewTOFUSession()
	require.NoError(err)
	session.WaitForDocument()
	serviceDesc, err := session.GetService("reunion")
	require.NoError(err)

	transport := &katzenpost.Transport{
		Session:   session,
		Recipient: serviceDesc.Name,
		Provider:  serviceDesc.Provider,
	}
	clock := new(catClock.Clock)
	epoch, _, _ := clock.Now()
	srv := []byte{1, 2, 3}
	passphrase1 := []byte("blah blah motorcycle pencil sharpening gas tank")
	passphrase2 := []byte("banana republic death squads with itchy trigger fingers")

	f := ""
	level := "DEBUG"
	disable := false
	logBackend, err := log.New(f, level, disable)
	require.NoError(err)

	var bobResult []byte
	var aliceResult []byte
	var nsaResult []byte
	var gchqResult []byte

	// client Alice

	alicePayload := []byte("Hello Bobby, what's up dude?")
	aliceContactID := uint64(1)
	aliceExchangelog := logBackend.GetLogger("alice_exchange")

	var wg sync.WaitGroup
	wg.Add(1)
	aliceUpdateCh := make(chan reunionClient.ReunionUpdate)
	shutdownCh := make(chan struct{})
	go func() {
		for {
			update := <-aliceUpdateCh
			if len(update.Result) > 0 {
				aliceResult = update.Result
				fmt.Printf("\n Alice got result: %s\n\n", update.Result)
				wg.Done()
			}
		}
	}()

	aliceExchange, err := reunionClient.NewExchange(alicePayload, aliceExchangelog, transport, aliceContactID, passphrase1, srv, epoch, aliceUpdateCh, shutdownCh)
	require.NoError(err)

	// bob client
	bobPayload := []byte("yo Alice, so you are a cryptographer and a language designer both?")
	bobContactID := uint64(2)
	bobLogBackend, err := log.New(f, level, disable)
	require.NoError(err)
	bobExchangelog := bobLogBackend.GetLogger("bob_exchange")

	wg.Add(1)
	bobUpdateCh := make(chan reunionClient.ReunionUpdate)
	go func() {
		for {
			update := <-bobUpdateCh
			if len(update.Result) > 0 {
				bobResult = update.Result
				fmt.Printf("\n Bob got result: %s\n\n", update.Result)
				wg.Done()
			}
		}
	}()

	bobExchange, err := reunionClient.NewExchange(bobPayload, bobExchangelog, transport, bobContactID, passphrase1, srv, epoch, bobUpdateCh, shutdownCh)
	require.NoError(err)

	// NSA client
	nsaPayload := []byte("yo GCHQ, sup?")
	nsaContactID := uint64(3)
	nsaLogBackend, err := log.New(f, level, disable)
	require.NoError(err)
	nsaExchangelog := nsaLogBackend.GetLogger("nsa_exchange")

	wg.Add(1)
	nsaUpdateCh := make(chan reunionClient.ReunionUpdate)
	go func() {
		for {
			update := <-nsaUpdateCh
			if len(update.Result) > 0 {
				nsaResult = update.Result
				fmt.Printf("\n Nsa got result: %s\n\n", update.Result)
				wg.Done()
			}
		}
	}()

	nsaExchange, err := reunionClient.NewExchange(nsaPayload, nsaExchangelog, transport, nsaContactID, passphrase2, srv, epoch, nsaUpdateCh, shutdownCh)
	require.NoError(err)

	// GCHQ client
	gchqPayload := []byte("yo NSA, what up")
	gchqContactID := uint64(4)
	gchqLogBackend, err := log.New(f, level, disable)
	require.NoError(err)
	gchqExchangelog := gchqLogBackend.GetLogger("gchq_exchange")

	wg.Add(1)
	gchqUpdateCh := make(chan reunionClient.ReunionUpdate)
	go func() {
		for {
			update := <-gchqUpdateCh
			if len(update.Result) > 0 {
				gchqResult = update.Result
				fmt.Printf("\n Gchq got result: %s\n\n", update.Result)
				wg.Done()
			}
		}
	}()

	gchqExchange, err := reunionClient.NewExchange(gchqPayload, gchqExchangelog, transport, gchqContactID, passphrase2, srv, epoch, gchqUpdateCh, shutdownCh)
	require.NoError(err)

	// Run reunion client exchanges.

	go aliceExchange.Run()
	go bobExchange.Run()
	go nsaExchange.Run()
	go gchqExchange.Run()

	wg.Wait()

	require.Equal(aliceResult, bobPayload)
	require.Equal(bobResult, alicePayload)
	require.Equal(nsaResult, gchqPayload)
	require.Equal(gchqResult, nsaPayload)
}

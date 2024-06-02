// main.go - Reunion http server.
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

package main

import (
	"fmt"
	"os"
	"sync"
	"testing"

	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/reunion/client"
	"github.com/katzenpost/katzenpost/reunion/epochtime/katzenpost"
	"github.com/katzenpost/katzenpost/reunion/transports/http"
	"github.com/stretchr/testify/require"
)

func NoTestHTTPServer2(t *testing.T) {
	require := require.New(t)

	address := "127.0.0.1:12345"
	urlPath := "/reunion"
	logPath := ""
	logLevel := "DEBUG"
	clock := new(katzenpost.Clock)
	stateFile, err := os.CreateTemp("", "catshadow_test_statefile")
	require.NoError(err)
	stateFile.Close()

	_, reunionServer, err := runHTTPServer(address, urlPath, logPath, logLevel, clock, stateFile.Name())
	require.NoError(err)

	epoch, _, _ := clock.Now()
	url := fmt.Sprintf("http://%s%s", address, urlPath)
	httpTransport := http.NewTransport(url)

	// variable shared among reunion clients
	f := ""
	level := "DEBUG"
	disable := false
	logBackend, err := log.New(f, level, disable)
	require.NoError(err)
	shutdownChan := make(chan struct{})

	srv := []byte{1, 2, 3}
	passphrase := []byte("blah blah motorcycle pencil sharpening gas tank")

	var bobResult []byte
	var aliceResult []byte

	// alice client
	alicePayload := []byte("Hello Bobby, what's up dude?")
	aliceContactID := uint64(1)
	require.NoError(err)
	aliceExchangelog := logBackend.GetLogger("alice_exchange")

	var wg sync.WaitGroup
	wg.Add(1)
	aliceUpdateCh := make(chan client.ReunionUpdate)
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

	aliceExchange, err := client.NewExchange(alicePayload, aliceExchangelog, httpTransport, aliceContactID, passphrase, srv, epoch, aliceUpdateCh, shutdownChan)
	require.NoError(err)

	// bob client
	bobPayload := []byte("Hello Alice, what's cracking?")
	bobContactID := uint64(2)
	require.NoError(err)
	bobExchangelog := logBackend.GetLogger("bob_exchange")

	wg.Add(1)
	bobUpdateCh := make(chan client.ReunionUpdate)
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

	bobExchange, err := client.NewExchange(bobPayload, bobExchangelog, httpTransport, bobContactID, passphrase, srv, epoch, bobUpdateCh, shutdownChan)
	require.NoError(err)

	go aliceExchange.Run()
	go bobExchange.Run()

	wg.Wait()
	close(shutdownChan)

	require.Equal(aliceResult, bobPayload)
	require.Equal(bobResult, alicePayload)

	reunionServer.Halt()
}

func NoTestHTTPServer3(t *testing.T) {
	require := require.New(t)

	address := "127.0.0.1:12345"
	urlPath := "/reunion"
	logPath := ""
	logLevel := "DEBUG"
	clock := new(katzenpost.Clock)
	stateFile, err := os.CreateTemp("", "catshadow_test_statefile")
	require.NoError(err)
	stateFile.Close()

	_, reunionServer, err := runHTTPServer(address, urlPath, logPath, logLevel, clock, stateFile.Name())
	require.NoError(err)

	epoch, _, _ := clock.Now()
	url := fmt.Sprintf("http://%s%s", address, urlPath)
	httpTransport := http.NewTransport(url)

	// variable shared among reunion clients
	f := ""
	level := "DEBUG"
	disable := false
	logBackend, err := log.New(f, level, disable)
	require.NoError(err)
	shutdownChan := make(chan struct{})

	srv := []byte{1, 2, 3}
	passphrase1 := []byte("blah blah motorcycle pencil sharpening gas tank")
	passphrase2 := []byte("a man a plan a canal panama, bitches")

	var bobResult []byte
	var aliceResult []byte
	var nsaResult []byte
	var gchqResult []byte

	// alice client
	alicePayload := []byte("Hello Bobby, what's up dude?")
	aliceContactID := uint64(1)
	require.NoError(err)
	aliceExchangelog := logBackend.GetLogger("alice_exchange")

	var wg sync.WaitGroup
	wg.Add(1)
	aliceUpdateCh := make(chan client.ReunionUpdate)
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

	aliceExchange, err := client.NewExchange(alicePayload, aliceExchangelog, httpTransport, aliceContactID, passphrase1, srv, epoch, aliceUpdateCh, shutdownChan)
	require.NoError(err)

	// bob client
	bobPayload := []byte("Hello Alice, what's cracking?")
	bobContactID := uint64(2)
	require.NoError(err)
	bobExchangelog := logBackend.GetLogger("bob_exchange")

	wg.Add(1)
	bobUpdateCh := make(chan client.ReunionUpdate)
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

	bobExchange, err := client.NewExchange(bobPayload, bobExchangelog, httpTransport, bobContactID, passphrase1, srv, epoch, bobUpdateCh, shutdownChan)
	require.NoError(err)

	// NSA client
	nsaPayload := []byte("Hello GCHQ, what's cracking?")
	nsaContactID := uint64(3)
	require.NoError(err)
	nsaExchangelog := logBackend.GetLogger("nsa_exchange")

	wg.Add(1)
	nsaUpdateCh := make(chan client.ReunionUpdate)
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

	nsaExchange, err := client.NewExchange(nsaPayload, nsaExchangelog, httpTransport, nsaContactID, passphrase2, srv, epoch, nsaUpdateCh, shutdownChan)
	require.NoError(err)

	// GCHQ client
	gchqPayload := []byte("Hello NSA, what's upper?")
	gchqContactID := uint64(4)
	require.NoError(err)
	gchqExchangelog := logBackend.GetLogger("gchq_exchange")

	wg.Add(1)
	gchqUpdateCh := make(chan client.ReunionUpdate)
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

	gchqExchange, err := client.NewExchange(gchqPayload, gchqExchangelog, httpTransport, gchqContactID, passphrase2, srv, epoch, gchqUpdateCh, shutdownChan)
	require.NoError(err)

	go aliceExchange.Run()
	go bobExchange.Run()
	go nsaExchange.Run()
	go gchqExchange.Run()

	wg.Wait()
	close(shutdownChan)

	require.Equal(aliceResult, bobPayload)
	require.Equal(bobResult, alicePayload)
	require.Equal(nsaResult, gchqPayload)
	require.Equal(gchqResult, nsaPayload)

	reunionServer.Halt()
}

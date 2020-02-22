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
	"context"
	"crypto/sha256"
	"fmt"
	"sync"
	"testing"

	"github.com/katzenpost/core/log"
	"github.com/katzenpost/reunion/client"
	"github.com/katzenpost/reunion/commands"
	"github.com/katzenpost/reunion/crypto"
	"github.com/katzenpost/reunion/transports/http"
	"github.com/stretchr/testify/require"
)

func TestHTTPServer1(t *testing.T) {
	require := require.New(t)

	address := "127.0.0.1:12345"
	urlPath := "/reunion"
	logPath := ""
	logLevel := "DEBUG"
	reunionServer := runHTTPServer(address, urlPath, logPath, logLevel)

	epoch := uint64(1234)
	url := fmt.Sprintf("http://%s%s", address, urlPath)
	httpTransport := http.NewTransport(url)

	myT1 := make([]byte, crypto.Type1MessageSize)
	blurb := []byte("cats and honeybadgers use cryptography for the win twice on sunday")
	copy(myT1[:len(blurb)], blurb)
	h := sha256.New()
	h.Write(myT1)
	myT1Hash := h.Sum(nil)
	myT1HashAr := [sha256.Size]byte{}
	copy(myT1HashAr[:], myT1Hash)

	sendT1Cmd := &commands.SendT1{
		Epoch:   epoch,
		Payload: myT1,
	}
	rawRequest := sendT1Cmd.ToBytes()
	sendT1Cmd2, err := commands.FromBytes(rawRequest)
	require.NoError(err)
	rawRequest2 := sendT1Cmd2.ToBytes()
	require.Equal(rawRequest, rawRequest2)

	serverReplyRaw, err := httpTransport.Query(sendT1Cmd)
	require.NoError(err)
	require.NotNil(serverReplyRaw)

	response, ok := serverReplyRaw.(*commands.MessageResponse)
	require.True(ok)
	require.Equal(response.ErrorCode, uint8(commands.ResponseStatusOK))

	sendFetch := &commands.FetchState{
		Epoch:  epoch,
		T1Hash: myT1HashAr,
	}

	serverReplyRaw, err = httpTransport.Query(sendFetch)
	require.NoError(err)
	require.NotNil(serverReplyRaw)

	reunionServer.Shutdown(context.TODO())
}

func TestHTTPServer2(t *testing.T) {
	require := require.New(t)

	address := "127.0.0.1:12345"
	urlPath := "/reunion"
	logPath := ""
	logLevel := "DEBUG"
	reunionServer := runHTTPServer(address, urlPath, logPath, logLevel)

	epoch := uint64(1234)
	url := fmt.Sprintf("http://%s%s", address, urlPath)
	httpTransport := http.NewTransport(url)

	// variable shared among reunion clients
	f := ""
	level := "DEBUG"
	disable := false
	logBackend, err := log.New(f, level, disable)
	require.NoError(err)

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

	aliceExchange, err := client.NewExchange(alicePayload, aliceExchangelog, httpTransport, aliceContactID, passphrase, srv, epoch, aliceUpdateCh)
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

	bobExchange, err := client.NewExchange(bobPayload, bobExchangelog, httpTransport, bobContactID, passphrase, srv, epoch, bobUpdateCh)
	require.NoError(err)

	go aliceExchange.Run()
	go bobExchange.Run()

	wg.Wait()

	require.Equal(aliceResult, bobPayload)
	require.Equal(bobResult, alicePayload)

	reunionServer.Shutdown(context.TODO())
}

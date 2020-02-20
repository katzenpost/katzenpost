// client_test.go - Reunion client tests.
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

// Package client provides the Reunion protocol client.
package client

import (
	"fmt"
	"sync"
	"testing"

	"github.com/katzenpost/core/log"
	"github.com/katzenpost/reunion/commands"
	"github.com/katzenpost/reunion/server"
	"github.com/stretchr/testify/require"
	"gopkg.in/op/go-logging.v1"
)

type MockReunionDB struct {
	server *server.Server
	log    *logging.Logger
}

func NewMockReunionDB(mylog *logging.Logger) *MockReunionDB {
	return &MockReunionDB{
		server: server.NewServer(),
		log:    mylog,
	}
}

func (m *MockReunionDB) Query(command commands.Command, haltCh chan interface{}) (commands.Command, error) {
	return m.server.ProcessQuery(command, haltCh)
}

func TestClientServerBasics1(t *testing.T) {
	require := require.New(t)

	// variable shared among reunion clients
	f := ""
	level := "DEBUG"
	disable := false
	logBackend, err := log.New(f, level, disable)
	require.NoError(err)

	dblog := logBackend.GetLogger("Reunion_DB")
	reunionDB := NewMockReunionDB(dblog)

	srv := []byte{1, 2, 3}
	passphrase := []byte("blah blah motorcycle pencil sharpening gas tank")
	epoch := uint64(12322)

	// alice client
	alicePayload := []byte("Hello Bobby, what's up dude?")
	aliceContactID := uint64(1)
	require.NoError(err)
	aliceExchangelog := logBackend.GetLogger("alice_exchange")

	var wg sync.WaitGroup
	wg.Add(1)
	aliceUpdateCh := make(chan ReunionUpdate)
	go func() {
		for {
			update := <-aliceUpdateCh
			if len(update.Result) > 0 {
				fmt.Printf("\n\n<>< Alice got result: %s\n\n", update.Result)
				wg.Done()
				break
			}
		}
	}()

	aliceExchange, err := NewExchange(alicePayload, aliceExchangelog, reunionDB, aliceContactID, passphrase, srv, epoch, aliceUpdateCh)
	require.NoError(err)

	// bob client
	bobPayload := []byte("yo Alice, so you are a cryptographer and a language designer both?")
	bobContactID := uint64(1)
	bobLogBackend, err := log.New(f, level, disable)
	require.NoError(err)
	bobExchangelog := bobLogBackend.GetLogger("bob_exchange")

	wg.Add(1)
	bobUpdateCh := make(chan ReunionUpdate)
	go func() {
		for {
			update := <-bobUpdateCh
			if len(update.Result) > 0 {
				fmt.Printf("\n\n<>< Bob got result: %s\n\n", update.Result)
				wg.Done()
				break
			}
		}
	}()

	bobExchange, err := NewExchange(bobPayload, bobExchangelog, reunionDB, bobContactID, passphrase, srv, epoch, bobUpdateCh)
	require.NoError(err)

	// Run the reunion client exchanges manually instead of using the Exchange method.
	fmt.Println("send t1 messages")
	hasAliceSent := aliceExchange.sendT1()
	fmt.Printf("Alice sent t1: %v\n", hasAliceSent)
	hasBobSent := bobExchange.sendT1()
	fmt.Printf("Bob sent t1: %v\n", hasBobSent)

	fmt.Println("fetching states")
	err = aliceExchange.fetchState()
	require.NoError(err)
	err = bobExchange.fetchState()
	require.NoError(err)

	fmt.Printf("Alice has received %d t1s\n", len(aliceExchange.receivedT1s))
	fmt.Printf("Bob has received %d t1s\n", len(bobExchange.receivedT1s))

	fmt.Println("send t2 messages")
	hasAliceSent = aliceExchange.sendT2Messages()
	fmt.Printf("Alice sent t2: %v\n", hasAliceSent)
	hasBobSent = bobExchange.sendT2Messages()
	fmt.Printf("Bob sent t2: %v\n", hasBobSent)

	fmt.Println("fetching states")
	err = aliceExchange.fetchState()
	require.NoError(err)
	err = bobExchange.fetchState()
	require.NoError(err)

	fmt.Printf("Alice has received %d t2s\n", len(aliceExchange.receivedT2s))
	fmt.Printf("Bob has received %d t2s\n", len(bobExchange.receivedT2s))

	fmt.Println("send t3 messages")
	hasAliceSent = aliceExchange.sendT3Messages()
	fmt.Printf("Alice sent t3: %v\n", hasAliceSent)
	hasBobSent = bobExchange.sendT3Messages()
	fmt.Printf("Bob sent t3: %v\n", hasBobSent)

	fmt.Println("last, fetching states")
	err = aliceExchange.fetchState()
	require.NoError(err)
	err = bobExchange.fetchState()
	require.NoError(err)

	aliceExchange.processT3Messages()
	aliceExchange.sentUpdateOK()

	bobExchange.processT3Messages()
	bobExchange.sentUpdateOK()

	// Wait for results from both clients.
	fmt.Println("waiting for finality")
	wg.Wait()
}

func TestClientServerBasics2(t *testing.T) {
	require := require.New(t)

	// variable shared among reunion clients
	f := ""
	level := "DEBUG"
	disable := false
	logBackend, err := log.New(f, level, disable)
	require.NoError(err)

	dblog := logBackend.GetLogger("Reunion_DB")
	reunionDB := NewMockReunionDB(dblog)

	srv := []byte{1, 2, 3}
	passphrase := []byte("blah blah motorcycle pencil sharpening gas tank")
	epoch := uint64(12322)

	// alice client
	alicePayload := []byte("sup")
	aliceContactID := uint64(1)
	require.NoError(err)
	aliceExchangelog := logBackend.GetLogger("alice_exchange")

	var wg sync.WaitGroup
	wg.Add(1)
	aliceUpdateCh := make(chan ReunionUpdate)
	go func() {
		for {
			update := <-aliceUpdateCh
			if len(update.Result) > 0 {
				fmt.Printf("\nAlice got result: %s\n\n", update.Result)
				wg.Done()
				break
			}
		}
	}()

	aliceExchange, err := NewExchange(alicePayload, aliceExchangelog, reunionDB, aliceContactID, passphrase, srv, epoch, aliceUpdateCh)
	require.NoError(err)

	// bob client
	bobPayload := []byte("yo")
	bobContactID := uint64(1)
	bobLogBackend, err := log.New(f, level, disable)
	require.NoError(err)
	bobExchangelog := bobLogBackend.GetLogger("bob_exchange")

	wg.Add(1)
	bobUpdateCh := make(chan ReunionUpdate)
	go func() {
		for {
			update := <-bobUpdateCh
			if len(update.Result) > 0 {
				fmt.Printf("\nBob got result: %s\n\n", update.Result)
				wg.Done()
				break
			}
		}
	}()

	bobExchange, err := NewExchange(bobPayload, bobExchangelog, reunionDB, bobContactID, passphrase, srv, epoch, bobUpdateCh)
	require.NoError(err)

	// Run reunion client exchanges.

	go aliceExchange.Run()
	go bobExchange.Run()

	wg.Wait()
}

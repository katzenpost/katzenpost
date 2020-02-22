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

func (m *MockReunionDB) Query(command commands.Command) (commands.Command, error) {
	return m.server.ProcessQuery(command)
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

	var bobResult []byte
	var aliceResult []byte

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
				aliceResult = update.Result
				fmt.Printf("\n Alice got result: %s\n\n", update.Result)
				wg.Done()
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
				bobResult = update.Result
				fmt.Printf("\n Bob got result: %s\n\n", update.Result)
				wg.Done()
			}
		}
	}()

	bobExchange, err := NewExchange(bobPayload, bobExchangelog, reunionDB, bobContactID, passphrase, srv, epoch, bobUpdateCh)
	require.NoError(err)

	// Run the reunion client exchanges manually instead of using the Exchange method.
	hasAliceSent := aliceExchange.sendT1()
	hasBobSent := bobExchange.sendT1()
	require.True(hasAliceSent)
	require.True(hasBobSent)

	err = aliceExchange.fetchState()
	require.NoError(err)
	err = bobExchange.fetchState()
	require.NoError(err)

	hasAliceSent = aliceExchange.sendT2Messages()
	hasBobSent = bobExchange.sendT2Messages()
	require.True(hasAliceSent)
	require.True(hasBobSent)

	err = aliceExchange.fetchState()
	require.NoError(err)
	err = bobExchange.fetchState()
	require.NoError(err)

	hasAliceSent = aliceExchange.sendT3Messages()
	hasBobSent = bobExchange.sendT3Messages()
	require.True(hasAliceSent)
	require.True(hasBobSent)

	err = aliceExchange.fetchState()
	require.NoError(err)
	err = bobExchange.fetchState()
	require.NoError(err)

	aliceExchange.processT3Messages()
	aliceExchange.sentUpdateOK()

	bobExchange.processT3Messages()
	bobExchange.sentUpdateOK()

	wg.Wait()

	require.Equal(aliceResult, bobPayload)
	require.Equal(bobResult, alicePayload)
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

	var bobResult []byte
	var aliceResult []byte

	// alice client
	alicePayload := []byte("sup bobby")
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
				aliceResult = update.Result
				fmt.Printf("\nAlice got result: %s\n\n", update.Result)
				wg.Done()
				break
			}
		}
	}()

	aliceExchange, err := NewExchange(alicePayload, aliceExchangelog, reunionDB, aliceContactID, passphrase, srv, epoch, aliceUpdateCh)
	require.NoError(err)

	// bob client
	bobPayload := []byte("yo alice")
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
				bobResult = update.Result
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

	require.Equal(aliceResult, bobPayload)
	require.Equal(bobResult, alicePayload)
}

func NoTestClientServerBasics3(t *testing.T) {
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

	var bobResult []byte
	var aliceResult []byte
	var nsaResult []byte

	// alice client
	alicePayload := []byte("sup bobby")
	aliceContactID := uint64(1)
	require.NoError(err)
	aliceExchangelog := logBackend.GetLogger("alice_exchange")

	var wg sync.WaitGroup
	wg.Add(2)
	aliceUpdateCh := make(chan ReunionUpdate)
	go func() {
		count := 0
		for {
			if count == 2 {
				return
			}
			update := <-aliceUpdateCh
			if update.Result != nil {
				if len(update.Result) > 0 {
					aliceResult = update.Result
					fmt.Printf("\nAlice got result: %s\n\n", update.Result)
					wg.Done()
					count++
				}
			}
		}
	}()

	aliceExchange, err := NewExchange(alicePayload, aliceExchangelog, reunionDB, aliceContactID, passphrase, srv, epoch, aliceUpdateCh)
	require.NoError(err)

	// bob client
	bobPayload := []byte("yo alice")
	bobContactID := uint64(1)
	bobLogBackend, err := log.New(f, level, disable)
	require.NoError(err)
	bobExchangelog := bobLogBackend.GetLogger("bob_exchange")

	wg.Add(2)
	bobUpdateCh := make(chan ReunionUpdate)
	go func() {
		count := 0
		for {
			if count == 2 {
				return
			}
			update := <-bobUpdateCh
			if update.Result != nil {
				if len(update.Result) > 0 {
					bobResult = update.Result
					fmt.Printf("\nBob got result: %s\n\n", update.Result)
					wg.Done()
					count++
				}
			}
		}
	}()

	bobExchange, err := NewExchange(bobPayload, bobExchangelog, reunionDB, bobContactID, passphrase, srv, epoch, bobUpdateCh)
	require.NoError(err)

	// nsa client
	nsaPayload := []byte("yo alice, this is the NSA")
	nsaContactID := uint64(1)
	nsaLogBackend, err := log.New(f, level, disable)
	require.NoError(err)
	nsaExchangelog := nsaLogBackend.GetLogger("nsa_exchange")

	wg.Add(2)
	nsaUpdateCh := make(chan ReunionUpdate)
	go func() {
		count := 0
		for {
			if count == 2 {
				return
			}
			update := <-nsaUpdateCh
			if update.Result != nil {
				if len(update.Result) > 0 {
					nsaResult = update.Result
					fmt.Printf("\nNsa got result: %s\n\n", update.Result)
					wg.Done()
					count++
				}
			}
		}
	}()

	nsaExchange, err := NewExchange(nsaPayload, nsaExchangelog, reunionDB, nsaContactID, passphrase, srv, epoch, nsaUpdateCh)
	require.NoError(err)

	// Run reunion client exchanges.

	go aliceExchange.Run()
	go bobExchange.Run()
	go nsaExchange.Run()

	wg.Wait()

	//require.Equal(aliceResult, bobPayload)
	//require.Equal(bobResult, alicePayload)
	//require.Equal(nsaResult, alicePayload)

	fmt.Printf("\n\nalice: %s\n\n bob: %s\n\n NSA: %s\n\n", aliceResult, bobResult, nsaResult)
}

func TestClientServerBasics4(t *testing.T) {
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
	passphrase1 := []byte("blah blah motorcycle pencil sharpening gas tank")
	passphrase2 := []byte("super secret spy trade craft pass phrase oh so clever")
	epoch := uint64(12322)

	var bobResult []byte
	var aliceResult []byte
	var nsaResult []byte
	var gchqResult []byte

	// alice client
	alicePayload := []byte("sup bobby")
	aliceContactID := uint64(1)
	require.NoError(err)
	aliceExchangelog := logBackend.GetLogger("alice_exchange")

	var wg sync.WaitGroup
	wg.Add(1)
	aliceUpdateCh := make(chan ReunionUpdate)
	go func() {
		for {
			update := <-aliceUpdateCh
			if update.Result != nil {
				if len(update.Result) > 0 {
					aliceResult = update.Result
					fmt.Printf("\nAlice got result: %s\n\n", update.Result)
					wg.Done()
				}
			}
		}
	}()

	aliceExchange, err := NewExchange(alicePayload, aliceExchangelog, reunionDB, aliceContactID, passphrase1, srv, epoch, aliceUpdateCh)
	require.NoError(err)

	// bob client
	bobPayload := []byte("yo alice")
	bobContactID := uint64(1)
	bobLogBackend, err := log.New(f, level, disable)
	require.NoError(err)
	bobExchangelog := bobLogBackend.GetLogger("bob_exchange")

	wg.Add(1)
	bobUpdateCh := make(chan ReunionUpdate)
	go func() {
		for {
			update := <-bobUpdateCh
			if update.Result != nil {
				if len(update.Result) > 0 {
					bobResult = update.Result
					fmt.Printf("\nBob got result: %s\n\n", update.Result)
					wg.Done()
				}
			}
		}
	}()

	bobExchange, err := NewExchange(bobPayload, bobExchangelog, reunionDB, bobContactID, passphrase1, srv, epoch, bobUpdateCh)
	require.NoError(err)

	// nsa client
	nsaPayload := []byte("ho GCHQ, this is the NSA")
	nsaContactID := uint64(1)
	nsaLogBackend, err := log.New(f, level, disable)
	require.NoError(err)
	nsaExchangelog := nsaLogBackend.GetLogger("nsa_exchange")

	wg.Add(1)
	nsaUpdateCh := make(chan ReunionUpdate)
	go func() {
		for {
			update := <-nsaUpdateCh
			if update.Result != nil {
				if len(update.Result) > 0 {
					nsaResult = update.Result
					fmt.Printf("\nNSA got result: %s\n\n", update.Result)
					wg.Done()
				}
			}
		}
	}()

	nsaExchange, err := NewExchange(nsaPayload, nsaExchangelog, reunionDB, nsaContactID, passphrase2, srv, epoch, nsaUpdateCh)
	require.NoError(err)

	// gchq client
	gchqPayload := []byte("yo NSA, this is the GCHQ")
	gchqContactID := uint64(1)
	gchqLogBackend, err := log.New(f, level, disable)
	require.NoError(err)
	gchqExchangelog := gchqLogBackend.GetLogger("gchq_exchange")

	wg.Add(1)
	gchqUpdateCh := make(chan ReunionUpdate)
	go func() {
		for {
			update := <-gchqUpdateCh
			if update.Result != nil {
				if len(update.Result) > 0 {
					gchqResult = update.Result
					fmt.Printf("\nGCHQ got result: %s\n\n", update.Result)
					wg.Done()
				}
			}
		}
	}()

	gchqExchange, err := NewExchange(gchqPayload, gchqExchangelog, reunionDB, gchqContactID, passphrase2, srv, epoch, gchqUpdateCh)
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

func TestClientStateSavingAndRecovery(t *testing.T) {
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

	var bobResult []byte
	var aliceResult []byte

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
				aliceResult = update.Result
				fmt.Printf("\n Alice got result: %s\n\n", update.Result)
				wg.Done()
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
				bobResult = update.Result
				fmt.Printf("\n Bob got result: %s\n\n", update.Result)
				wg.Done()
			}
		}
	}()

	bobExchange, err := NewExchange(bobPayload, bobExchangelog, reunionDB, bobContactID, passphrase, srv, epoch, bobUpdateCh)
	require.NoError(err)

	// Run the reunion client exchanges manually instead of using the Exchange method.
	hasAliceSent := aliceExchange.sendT1()
	hasBobSent := bobExchange.sendT1()
	require.True(hasAliceSent)
	require.True(hasBobSent)

	aliceSerialized, err := aliceExchange.Marshal()
	require.NoError(err)
	aliceExchange, err = NewExchangeFromSnapshot(aliceSerialized, aliceExchangelog, reunionDB, aliceUpdateCh)
	require.NoError(err)

	bobSerialized, err := bobExchange.Marshal()
	require.NoError(err)
	bobExchange, err = NewExchangeFromSnapshot(bobSerialized, bobExchangelog, reunionDB, bobUpdateCh)
	require.NoError(err)

	err = aliceExchange.fetchState()
	require.NoError(err)
	err = bobExchange.fetchState()
	require.NoError(err)

	hasAliceSent = aliceExchange.sendT2Messages()
	hasBobSent = bobExchange.sendT2Messages()
	require.True(hasAliceSent)
	require.True(hasBobSent)

	err = aliceExchange.fetchState()
	require.NoError(err)
	err = bobExchange.fetchState()
	require.NoError(err)

	aliceSerialized, err = aliceExchange.Marshal()
	require.NoError(err)
	aliceExchange, err = NewExchangeFromSnapshot(aliceSerialized, aliceExchangelog, reunionDB, aliceUpdateCh)
	require.NoError(err)

	bobSerialized, err = bobExchange.Marshal()
	require.NoError(err)
	bobExchange, err = NewExchangeFromSnapshot(bobSerialized, bobExchangelog, reunionDB, bobUpdateCh)
	require.NoError(err)

	hasAliceSent = aliceExchange.sendT3Messages()
	hasBobSent = bobExchange.sendT3Messages()
	require.True(hasAliceSent)
	require.True(hasBobSent)

	err = aliceExchange.fetchState()
	require.NoError(err)
	err = bobExchange.fetchState()
	require.NoError(err)

	aliceSerialized, err = aliceExchange.Marshal()
	require.NoError(err)
	aliceExchange, err = NewExchangeFromSnapshot(aliceSerialized, aliceExchangelog, reunionDB, aliceUpdateCh)
	require.NoError(err)

	bobSerialized, err = bobExchange.Marshal()
	require.NoError(err)
	bobExchange, err = NewExchangeFromSnapshot(bobSerialized, bobExchangelog, reunionDB, bobUpdateCh)
	require.NoError(err)

	aliceExchange.processT3Messages()
	bobExchange.processT3Messages()

	wg.Wait()

	require.Equal(aliceResult, bobPayload)
	require.Equal(bobResult, alicePayload)
}

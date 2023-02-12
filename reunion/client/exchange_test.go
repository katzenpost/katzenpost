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
	"path/filepath"
	"os"
	"sync"
	"testing"

	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/reunion/commands"
	"github.com/katzenpost/katzenpost/reunion/epochtime"
	"github.com/katzenpost/katzenpost/reunion/epochtime/katzenpost"
	"github.com/katzenpost/katzenpost/reunion/server"
	"github.com/stretchr/testify/require"
	"gopkg.in/op/go-logging.v1"
)

type MockReunionDB struct {
	server *server.Server
	log    *logging.Logger
}

func NewMockReunionDB(pathPrefix string, mylog *logging.Logger, clock epochtime.EpochClock) (*MockReunionDB, error) {
	debugs, debuge := os.Stat(pathPrefix)
	if debuge != nil {
		panic("mockdir stat failed")
	} else if !debugs.IsDir() {
		panic("mockdir is not dir")
	}
	stateFileName := filepath.Join(pathPrefix, "catshadow_test_statefile")

	logPath := ""
	logLevel := "DEBUG"
	s, err := server.NewServer(clock, stateFileName, logPath, logLevel)
	return &MockReunionDB{
		server: s,
		log:    mylog,
	}, err
}

func (m *MockReunionDB) Halt() {
	m.server.Halt()
}

func (m *MockReunionDB) Query(command commands.Command) (commands.Command, error) {
	return m.server.ProcessQuery(command)
}

func (m *MockReunionDB) CurrentEpochs() ([]uint64, error) {
	clock := new(katzenpost.Clock)
	epoch, _, _ := clock.Now()
	return []uint64{epoch - 1, epoch, epoch + 1}, nil
}

func (m *MockReunionDB) CurrentSharedRandoms() ([][]byte, error) {
	return [][]byte{[]byte{1, 2, 3}, []byte("bbq"), []byte("lol")}, nil
}

func TestClientServerBasics1(t *testing.T) {
	t.Parallel()
	require := require.New(t)

	// variable shared among reunion clients
	f := ""
	level := "DEBUG"
	disable := false
	logBackend, err := log.New(f, level, disable)
	require.NoError(err)
	shutdownChan := make(chan struct{})

	clock := new(katzenpost.Clock)
	epoch, _, _ := clock.Now()
	dblog := logBackend.GetLogger("Reunion_DB")
	reunionDB, err := NewMockReunionDB(t.TempDir(), dblog, clock)
	require.NoError(err)

	srv := []byte{1, 2, 3}
	passphrase := []byte("blah blah motorcycle pencil sharpening gas tank")

	var bobResult []byte
	var aliceResult []byte

	// alice client
	alicePayload := []byte("Hello Bobby, what's up dude?")
	aliceContactID := uint64(1)
	aliceExchangelog := logBackend.GetLogger("alice_exchange")

	var wg sync.WaitGroup
	wg.Add(1)
	aliceUpdateCh := make(chan ReunionUpdate)
	go func() {
		for {
			update := <-aliceUpdateCh
			require.NoError(update.Error)
			if len(update.Result) > 0 {
				aliceResult = update.Result
				t.Log("Alice got result:", update.Result)
				break
			}
		}
		wg.Done()
	}()

	aliceExchange, err := NewExchange(alicePayload, aliceExchangelog, reunionDB, aliceContactID, passphrase, srv, epoch, aliceUpdateCh, shutdownChan)
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
			update := <-bobUpdateCh // this never gets shut down
			require.NoError(update.Error)
			if len(update.Result) > 0 {
				bobResult = update.Result
				t.Log("Bob got result:", update.Result)
				break
			}
		}
		wg.Done()
	}()

	bobExchange, err := NewExchange(bobPayload, bobExchangelog, reunionDB, bobContactID, passphrase, srv, epoch, bobUpdateCh, shutdownChan)
	require.NoError(err)

	// Run the reunion client exchanges manually instead of using the Exchange method.
	hasAliceSent := aliceExchange.sendT1()
	hasBobSent := bobExchange.sendT1()
	require.NoError(hasAliceSent)
	require.NoError(hasBobSent)

	err = aliceExchange.fetchState()
	require.NoError(err)
	err = bobExchange.fetchState()
	require.NoError(err)

	hasAliceSent = aliceExchange.sendT2Messages()
	hasBobSent = bobExchange.sendT2Messages()
	require.NoError(hasAliceSent)
	require.NoError(hasBobSent)

	err = aliceExchange.fetchState()
	require.NoError(err)
	err = bobExchange.fetchState()
	require.NoError(err)

	hasAliceSent = aliceExchange.sendT3Messages()
	hasBobSent = bobExchange.sendT3Messages()
	require.NoError(hasAliceSent)
	require.NoError(hasBobSent)

	err = aliceExchange.fetchState()
	require.NoError(err)
	err = bobExchange.fetchState()
	require.NoError(err)

	aDidProcess := aliceExchange.processT3Messages()
	t.Log("alice processT3Messages", aDidProcess)
	bDidProcess := bobExchange.processT3Messages()
	t.Log("bob processT3Messages", bDidProcess)
	aliceExchange.sentUpdateOK()
	// this blocks for 30min in e.updateChan <- ReunionUpdate

	bobExchange.sentUpdateOK()

	wg.Wait()
	reunionDB.Halt()
	close(shutdownChan)

	require.Equal(aliceResult, bobPayload)
	require.Equal(bobResult, alicePayload)
}

func TestClientServerBasics2(t *testing.T) {
	t.Parallel()
	require := require.New(t)

	// variable shared among reunion clients
	f := ""
	level := "DEBUG"
	disable := false
	logBackend, err := log.New(f, level, disable)
	require.NoError(err)
	shutdownChan := make(chan struct {})

	clock := new(katzenpost.Clock)
	epoch, _, _ := clock.Now()
	dblog := logBackend.GetLogger("Reunion_DB")
	reunionDB, err := NewMockReunionDB(t.TempDir(), dblog, clock)
	require.NoError(err)

	srv := []byte{1, 2, 3}
	passphrase := []byte("blah blah motorcycle pencil sharpening gas tank")

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

	aliceExchange, err := NewExchange(alicePayload, aliceExchangelog, reunionDB, aliceContactID, passphrase, srv, epoch, aliceUpdateCh, shutdownChan)
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

	bobExchange, err := NewExchange(bobPayload, bobExchangelog, reunionDB, bobContactID, passphrase, srv, epoch, bobUpdateCh, shutdownChan)
	require.NoError(err)

	// Run reunion client exchanges.

	wg.Add(1)
	go func() {
		aliceExchange.Run()
		wg.Done()
	}()
	wg.Add(1)
	go func() {
		bobExchange.Run()
		wg.Done()
	}()

	wg.Wait()
	reunionDB.Halt()
	close(shutdownChan)

	require.Equal(aliceResult, bobPayload)
	require.Equal(bobResult, alicePayload)
}

func NoTestClientServerBasics3(t *testing.T) {
	t.Parallel()
	require := require.New(t)

	// variable shared among reunion clients
	f := ""
	level := "DEBUG"
	disable := false
	logBackend, err := log.New(f, level, disable)
	require.NoError(err)
	shutdownChan := make(chan struct {})

	clock := new(katzenpost.Clock)
	epoch, _, _ := clock.Now()
	dblog := logBackend.GetLogger("Reunion_DB")
	reunionDB, err := NewMockReunionDB(t.TempDir(), dblog, clock)
	require.NoError(err)

	srv := []byte{1, 2, 3}
	passphrase := []byte("blah blah motorcycle pencil sharpening gas tank")

	var bobResult []byte
	var aliceResult []byte
	var nsaResult []byte

	// alice client
	alicePayload := []byte("sup bobby")
	aliceContactID := uint64(1)
	require.NoError(err)
	aliceExchangelog := logBackend.GetLogger("alice_exchange")

	var wg sync.WaitGroup
	wg.Add(1)
	aliceUpdateCh := make(chan ReunionUpdate)
	go func() {
		count := 0
		for {
			if count == 2 {
				break
			}
			update := <-aliceUpdateCh
			if update.Result != nil {
				if len(update.Result) > 0 {
					aliceResult = update.Result
					t.Log("Alice got result:", update.Result)
					count++
				}
			}
		}
		wg.Done()
	}()

	aliceExchange, err := NewExchange(alicePayload, aliceExchangelog, reunionDB, aliceContactID, passphrase, srv, epoch, aliceUpdateCh, shutdownChan)
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
		count := 0
		for {
			if count == 2 {
				break
			}
			update := <-bobUpdateCh
			if update.Result != nil {
				if len(update.Result) > 0 {
					bobResult = update.Result
					t.Log("Bob got result:", update.Result)
					count++
				}
			}
		}
		wg.Done()
	}()

	bobExchange, err := NewExchange(bobPayload, bobExchangelog, reunionDB, bobContactID, passphrase, srv, epoch, bobUpdateCh, shutdownChan)
	require.NoError(err)

	// nsa client
	nsaPayload := []byte("yo alice, this is the NSA")
	nsaContactID := uint64(1)
	nsaLogBackend, err := log.New(f, level, disable)
	require.NoError(err)
	nsaExchangelog := nsaLogBackend.GetLogger("nsa_exchange")

	wg.Add(1)
	nsaUpdateCh := make(chan ReunionUpdate)
	go func() {
		count := 0
		for {
			if count == 2 {
				break
			}
			update := <-nsaUpdateCh
			if update.Result != nil {
				if len(update.Result) > 0 {
					nsaResult = update.Result
					t.Log("Nsa got result:", update.Result)
					count++
				}
			}
		}
		wg.Done()
	}()

	nsaExchange, err := NewExchange(nsaPayload, nsaExchangelog, reunionDB, nsaContactID, passphrase, srv, epoch, nsaUpdateCh, shutdownChan)
	require.NoError(err)

	// Run reunion client exchanges.

	wg.Add(3)
	go func() {
		aliceExchange.Run()
		wg.Done()
	}()
	go func(){
		bobExchange.Run()
		wg.Done()
	}()
	go func() {
		nsaExchange.Run()
		wg.Done()
	}()

	wg.Wait()
	reunionDB.Halt()
	close(shutdownChan)

	//require.Equal(aliceResult, bobPayload)
	//require.Equal(bobResult, alicePayload)
	//require.Equal(nsaResult, alicePayload)

	fmt.Printf("\n\nalice: %s\n\n bob: %s\n\n NSA: %s\n\n", aliceResult, bobResult, nsaResult)
}

func TestClientServerBasics4(t *testing.T) {
	t.Parallel()
	require := require.New(t)

	// variable shared among reunion clients
	f := ""
	level := "DEBUG"
	disable := false
	logBackend, err := log.New(f, level, disable)
	require.NoError(err)
	shutdownChan := make(chan struct {})

	clock := new(katzenpost.Clock)
	epoch, _, _ := clock.Now()
	dblog := logBackend.GetLogger("Reunion_DB")
	reunionDB, err := NewMockReunionDB(t.TempDir(), dblog, clock)
	require.NoError(err)

	srv := []byte{1, 2, 3}
	passphrase1 := []byte("blah blah motorcycle pencil sharpening gas tank")
	passphrase2 := []byte("super secret spy trade craft pass phrase oh so clever")

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
					break
				}
			}
		}
		wg.Done()
	}()

	aliceExchange, err := NewExchange(alicePayload, aliceExchangelog, reunionDB, aliceContactID, passphrase1, srv, epoch, aliceUpdateCh, shutdownChan)
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
					break
				}
			}
		}
		wg.Done()
	}()

	bobExchange, err := NewExchange(bobPayload, bobExchangelog, reunionDB, bobContactID, passphrase1, srv, epoch, bobUpdateCh, shutdownChan)
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
					break
				}
			}
		}
		wg.Done()
	}()

	nsaExchange, err := NewExchange(nsaPayload, nsaExchangelog, reunionDB, nsaContactID, passphrase2, srv, epoch, nsaUpdateCh, shutdownChan)
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
					break
				}
			}
		}
		wg.Done()
	}()

	gchqExchange, err := NewExchange(gchqPayload, gchqExchangelog, reunionDB, gchqContactID, passphrase2, srv, epoch, gchqUpdateCh, shutdownChan)
	require.NoError(err)

	// Run reunion client exchanges.

	wg.Add(4)
	go func() {
		aliceExchange.Run()
		wg.Done()
	}()
	go func() {
		bobExchange.Run()
		wg.Done()
	}()
	go func() {
		nsaExchange.Run()
		wg.Done()
	}()
	go func() {
		gchqExchange.Run()
		wg.Done()
	}()

	wg.Wait()
	reunionDB.Halt()

	t.Log("comparing results in TestClientServerBasics4 after wg.Wait()")
	require.Equal(aliceResult, bobPayload)
	require.Equal(bobResult, alicePayload)
	require.Equal(nsaResult, gchqPayload)
	require.Equal(gchqResult, nsaPayload)
}

func TestClientStateSavingAndRecovery(t *testing.T) {
	t.Parallel()
	require := require.New(t)

	// variable shared among reunion clients
	f := ""
	level := "DEBUG"
	disable := false
	logBackend, err := log.New(f, level, disable)
	require.NoError(err)
	shutdownChan := make(chan struct {})

	clock := new(katzenpost.Clock)
	epoch, _, _ := clock.Now()
	dblog := logBackend.GetLogger("Reunion_DB")
	reunionDB, err := NewMockReunionDB(t.TempDir(), dblog, clock)
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
	aliceUpdateCh := make(chan ReunionUpdate)
	go func() {
		for {
			update := <-aliceUpdateCh
			if len(update.Result) > 0 {
				aliceResult = update.Result
				fmt.Printf("\n Alice got result: %s\n\n", update.Result)
				wg.Done()
				break
			}
		}
	}()

	aliceExchange, err := NewExchange(alicePayload, aliceExchangelog, reunionDB, aliceContactID, passphrase, srv, epoch, aliceUpdateCh, shutdownChan)
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
				break
			}
		}
	}()

	bobExchange, err := NewExchange(bobPayload, bobExchangelog, reunionDB, bobContactID, passphrase, srv, epoch, bobUpdateCh, shutdownChan)
	require.NoError(err)

	// Run the reunion client exchanges manually instead of using the Exchange method.
	hasAliceSent := aliceExchange.sendT1()
	hasBobSent := bobExchange.sendT1()
	require.NoError(hasAliceSent)
	require.NoError(hasBobSent)

	aliceSerialized, err := aliceExchange.Marshal()
	require.NoError(err)
	aliceExchange, err = NewExchangeFromSnapshot(aliceSerialized, aliceExchangelog, reunionDB, aliceUpdateCh, shutdownChan)
	require.NoError(err)

	bobSerialized, err := bobExchange.Marshal()
	require.NoError(err)
	bobExchange, err = NewExchangeFromSnapshot(bobSerialized, bobExchangelog, reunionDB, bobUpdateCh, shutdownChan)
	require.NoError(err)

	err = aliceExchange.fetchState()
	require.NoError(err)
	err = bobExchange.fetchState()
	require.NoError(err)

	hasAliceSent = aliceExchange.sendT2Messages()
	hasBobSent = bobExchange.sendT2Messages()
	require.NoError(hasAliceSent)
	require.NoError(hasBobSent)

	err = aliceExchange.fetchState()
	require.NoError(err)
	err = bobExchange.fetchState()
	require.NoError(err)

	aliceSerialized, err = aliceExchange.Marshal()
	require.NoError(err)
	aliceExchange, err = NewExchangeFromSnapshot(aliceSerialized, aliceExchangelog, reunionDB, aliceUpdateCh, shutdownChan)
	require.NoError(err)

	bobSerialized, err = bobExchange.Marshal()
	require.NoError(err)
	bobExchange, err = NewExchangeFromSnapshot(bobSerialized, bobExchangelog, reunionDB, bobUpdateCh, shutdownChan)
	require.NoError(err)

	hasAliceSent = aliceExchange.sendT3Messages()
	hasBobSent = bobExchange.sendT3Messages()
	require.NoError(hasAliceSent)
	require.NoError(hasBobSent)

	err = aliceExchange.fetchState()
	require.NoError(err)
	err = bobExchange.fetchState()
	require.NoError(err)

	aliceSerialized, err = aliceExchange.Marshal()
	require.NoError(err)
	aliceExchange, err = NewExchangeFromSnapshot(aliceSerialized, aliceExchangelog, reunionDB, aliceUpdateCh, shutdownChan)
	require.NoError(err)

	bobSerialized, err = bobExchange.Marshal()
	require.NoError(err)
	bobExchange, err = NewExchangeFromSnapshot(bobSerialized, bobExchangelog, reunionDB, bobUpdateCh, shutdownChan)
	require.NoError(err)

	aliceExchange.processT3Messages()
	bobExchange.processT3Messages()

	wg.Wait()
	reunionDB.Halt()


	require.Equal(aliceResult, bobPayload)
	require.Equal(bobResult, alicePayload)
}

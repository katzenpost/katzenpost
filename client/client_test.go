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

func TestClientServerBasics(t *testing.T) {
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
				fmt.Printf("Alice got result: %s", update.Result)
				defer wg.Done()
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

	bobUpdateCh := make(chan ReunionUpdate)
	go func() {
		for {
			update := <-bobUpdateCh
			if len(update.Result) > 0 {
				fmt.Printf("Bob got result: %s", update.Result)
				defer wg.Done()
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

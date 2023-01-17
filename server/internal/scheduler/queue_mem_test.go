// queue_mem_test.go - Katzenpost scheduler memory queue tests.
// Copyright (C) 2019 Masala.
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

package scheduler

import (
	"github.com/katzenpost/katzenpost/core/crypto/sign"
	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/core/sphinx"
	"github.com/katzenpost/katzenpost/core/thwack"
	"github.com/katzenpost/katzenpost/core/wire"
	"github.com/katzenpost/katzenpost/server/config"
	"github.com/katzenpost/katzenpost/server/internal/glue"
	"github.com/katzenpost/katzenpost/server/internal/packet"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

type mockServer struct {
	connector glue.Connector
}
type mockGlue struct {
	s mockServer
}

func (m *mockGlue) Config() *config.Config {
	c := &config.Config{}
	c.Debug = &config.Debug{}
	return c
}
func (m *mockGlue) Connector() glue.Connector {
	return m.s.connector
}
func (m *mockGlue) Decoy() glue.Decoy {
	var d glue.Decoy
	return d
}
func (m *mockGlue) IdentityKey() sign.PrivateKey {
	return nil
}

func (m *mockGlue) IdentityPublicKey() sign.PublicKey {
	return nil
}

func (m *mockGlue) LinkKey() wire.PrivateKey {
	return nil
}
func (m *mockGlue) Listeners() []glue.Listener {
	return make([]glue.Listener, 0)
}
func (m *mockGlue) LogBackend() *log.Backend {
	return nil
}
func (m *mockGlue) Management() *thwack.Server {
	return nil
}
func (m *mockGlue) MixKeys() glue.MixKeys {
	return nil
}
func (m *mockGlue) PKI() glue.PKI {
	return nil
}
func (m *mockGlue) Provider() glue.Provider {
	return nil
}
func (m *mockGlue) Scheduler() glue.Scheduler {
	return nil
}
func (m *mockGlue) ReshadowCryptoWorkers() {}

// TestMemoryQueueBulkEnqueue verifies that the queue orders packets by delay
func TestMemoryQueueBulkEnqueue(t *testing.T) {
	require := require.New(t)
	g := new(mockGlue)
	logger, err := log.New("", "DEBUG", false)
	require.NoError(err)
	q := newMemoryQueue(g, logger.GetLogger("mq"))
	pkts := make([]*packet.Packet, 100)

	geo := sphinx.DefaultGeometry()

	payload := make([]byte, geo.PacketLength)
	for i := 0; i < 100; i++ {
		// create a set of packets with out-of-order delays
		pkts[i], err = packet.New(payload)
		require.NoError(err)
		pkts[i].Delay = time.Millisecond * time.Duration((i%2)*400+i*5+40)
	}
	last := pkts[0].Delay
	q.BulkEnqueue(pkts)
	for i := 0; i < 100; i++ {
		_, pkt := q.Peek()
		require.NotNil(pkt)
		// ensure ordering by priority is correct
		require.True(pkt.Delay >= last)
		last = pkt.Delay
		q.Pop()
	}

	_, isnil := q.Peek()
	require.True(isnil == nil)
	q.Pop() // don't panic
}

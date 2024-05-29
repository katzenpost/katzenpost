// SPDX-FileCopyrightText: Copyright (C) 2019 Masala.
// SPDX-License-Identifier: AGPL 3.0

package scheduler

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/kem"
	ecdh "github.com/katzenpost/hpqc/nike/x25519"
	"github.com/katzenpost/hpqc/rand"
	"github.com/katzenpost/hpqc/sign"

	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/katzenpost/katzenpost/server/config"
	"github.com/katzenpost/katzenpost/server/internal/glue"
	"github.com/katzenpost/katzenpost/server/internal/packet"
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

func (m *mockGlue) LinkKey() kem.PrivateKey {
	return nil
}
func (m *mockGlue) Listeners() []glue.Listener {
	return make([]glue.Listener, 0)
}
func (m *mockGlue) LogBackend() *log.Backend {
	return nil
}
func (m *mockGlue) MixKeys() glue.MixKeys {
	return nil
}
func (m *mockGlue) PKI() glue.PKI {
	return nil
}
func (m *mockGlue) Gateway() glue.Gateway {
	return nil
}
func (m *mockGlue) ServiceNode() glue.ServiceNode {
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

	geo := geo.GeometryFromUserForwardPayloadLength(
		ecdh.Scheme(rand.Reader),
		2000,
		true,
		5,
	)

	payload := make([]byte, geo.PacketLength)
	for i := 0; i < 100; i++ {
		// create a set of packets with out-of-order delays
		pkts[i], err = packet.New(payload, geo)
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

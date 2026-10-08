// SPDX-License-Identifier: AGPL-3.0-only

package kaetzchen

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	ecdh "github.com/katzenpost/hpqc/nike/x25519"
	"github.com/katzenpost/hpqc/rand"

	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/core/sphinx"
	"github.com/katzenpost/katzenpost/core/sphinx/commands"
	sConstants "github.com/katzenpost/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/katzenpost/katzenpost/server/config"
	"github.com/katzenpost/katzenpost/server/internal/packet"
)

type captureScheduler struct{ ch chan *packet.Packet }

func (s *captureScheduler) Halt()                   {}
func (s *captureScheduler) OnNewMixMaxDelay(uint64) {}
func (s *captureScheduler) OnPacket(p *packet.Packet) {
	s.ch <- p
}

func TestReplyNodeDelayIsMilliseconds(t *testing.T) {
	nike := ecdh.Scheme(rand.Reader)
	g := geo.GeometryFromUserForwardPayloadLength(nike, 2000, true, 5)
	s, err := sphinx.FromGeometry(g)
	require.NoError(t, err)

	pub, _, err := nike.GenerateKeyPair()
	require.NoError(t, err)
	hop := &sphinx.PathHop{NIKEPublicKey: pub}
	_, err = rand.Reader.Read(hop.ID[:])
	require.NoError(t, err)
	hop.Commands = []commands.RoutingCommand{new(commands.Recipient), new(commands.SURBReply)}
	surb, _, err := s.NewSURB(rand.Reader, []*sphinx.PathHop{hop})
	require.NoError(t, err)

	logBackend, err := log.New("", "DEBUG", false)
	require.NoError(t, err)
	sched := &captureScheduler{ch: make(chan *packet.Packet, 1)}
	goo := &mockGlue{s: &mockServer{
		logBackend: logBackend,
		scheduler:  sched,
		cfg:        &config.Config{SphinxGeometry: g, Debug: &config.Debug{}},
	}}
	k := &KaetzchenWorker{
		glue:      goo,
		log:       logBackend.GetLogger("test"),
		kaetzchen: make(map[[sConstants.RecipientIDLength]byte]Kaetzchen),
	}
	var recipient [sConstants.RecipientIDLength]byte
	copy(recipient[:], "+test")
	k.kaetzchen[recipient] = &MockKaetzchen{receivedCh: make(chan bool, 1)}

	pkt, err := packet.New(make([]byte, g.PacketLength), g)
	require.NoError(t, err)
	pkt.Recipient = &commands.Recipient{ID: recipient}
	pkt.Payload = make([]byte, g.ForwardPayloadLength)
	pkt.Payload[0] = 1
	copy(pkt.Payload[g.SphinxPlaintextHeaderLength:], surb)
	pkt.RecvAt = time.Now()
	pkt.Delay = 5 * time.Second

	k.processKaetzchen(pkt)
	resp := <-sched.ch
	require.LessOrEqual(t, resp.NodeDelay.Delay, uint32(5000))
	require.Greater(t, resp.NodeDelay.Delay, uint32(4000))
	require.Equal(t, time.Duration(resp.NodeDelay.Delay)*time.Millisecond, resp.Delay.Truncate(time.Millisecond))
}

// SPDX-License-Identifier: AGPL-3.0-only

package service

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/kem"
	ecdh "github.com/katzenpost/hpqc/nike/x25519"
	"github.com/katzenpost/hpqc/rand"
	"github.com/katzenpost/hpqc/sign"

	"github.com/katzenpost/katzenpost/core/connlimit"
	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/core/sphinx"
	"github.com/katzenpost/katzenpost/core/sphinx/commands"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/katzenpost/katzenpost/core/thwack"
	"github.com/katzenpost/katzenpost/server/config"
	"github.com/katzenpost/katzenpost/server/internal/glue"
	"github.com/katzenpost/katzenpost/server/internal/packet"
)

type reply struct {
	at  time.Time
	pkt *packet.Packet
}

type replyScheduler struct {
	ch chan reply
}

func (s *replyScheduler) Halt()                   {}
func (s *replyScheduler) OnNewMixMaxDelay(uint64) {}
func (s *replyScheduler) OnPacket(pkt *packet.Packet) {
	s.ch <- reply{at: time.Now(), pkt: pkt}
}

type serviceGlue struct {
	cfg   *config.Config
	log   *log.Backend
	sched *replyScheduler
}

func (g *serviceGlue) Config() *config.Config            { return g.cfg }
func (g *serviceGlue) LogBackend() *log.Backend          { return g.log }
func (g *serviceGlue) IdentityKey() sign.PrivateKey      { return nil }
func (g *serviceGlue) IdentityPublicKey() sign.PublicKey { return nil }
func (g *serviceGlue) LinkKey() kem.PrivateKey           { return nil }
func (g *serviceGlue) Management() *thwack.Server        { return nil }
func (g *serviceGlue) MixKeys() glue.MixKeys             { return nil }
func (g *serviceGlue) PKI() glue.PKI                     { return nil }
func (g *serviceGlue) Gateway() glue.Gateway             { return nil }
func (g *serviceGlue) ServiceNode() glue.ServiceNode     { return nil }
func (g *serviceGlue) Scheduler() glue.Scheduler         { return g.sched }
func (g *serviceGlue) Connector() glue.Connector         { return nil }
func (g *serviceGlue) Listeners() []glue.Listener        { return nil }
func (g *serviceGlue) Decoy() glue.Decoy                 { return nil }
func (g *serviceGlue) PeerConnSet() *connlimit.PeerSet   { return nil }
func (g *serviceGlue) ReshadowCryptoWorkers()            {}

func newServiceGlue(t *testing.T, debug config.Debug) *serviceGlue {
	backend, err := log.New("", "ERROR", false)
	require.NoError(t, err)
	debug.NumServiceWorkers = 1
	debug.NumKaetzchenWorkers = 1
	debug.ServiceDelay = 1000
	debug.KaetzchenDelay = 1000
	return &serviceGlue{
		log:   backend,
		sched: &replyScheduler{ch: make(chan reply, 8)},
		cfg: &config.Config{
			Server:     &config.Server{IsServiceNode: true},
			Logging:    &config.Logging{},
			Management: &config.Management{},
			ServiceNode: &config.ServiceNode{
				Kaetzchen: []*config.Kaetzchen{{
					Capability: "echo",
					Endpoint:   "echo",
					Config:     map[string]interface{}{},
				}},
			},
			PKI:            &config.PKI{},
			Debug:          &debug,
			SphinxGeometry: geo.GeometryFromUserForwardPayloadLength(ecdh.Scheme(rand.Reader), 2000, true, 5),
		},
	}
}

func echoRequest(t *testing.T, g *geo.Geometry, delay time.Duration) *packet.Packet {
	nike := ecdh.Scheme(rand.Reader)
	pub, _, err := nike.GenerateKeyPair()
	require.NoError(t, err)
	hop := &sphinx.PathHop{NIKEPublicKey: pub}
	_, err = rand.Reader.Read(hop.ID[:])
	require.NoError(t, err)
	surbReply := &commands.SURBReply{}
	_, err = rand.Reader.Read(surbReply.ID[:])
	require.NoError(t, err)
	hop.Commands = []commands.RoutingCommand{&commands.Recipient{}, surbReply}
	s, err := sphinx.FromGeometry(g)
	require.NoError(t, err)
	surb, _, err := s.NewSURB(rand.Reader, []*sphinx.PathHop{hop})
	require.NoError(t, err)

	pkt, err := packet.New(make([]byte, g.PacketLength), g)
	require.NoError(t, err)
	pkt.Payload = make([]byte, g.ForwardPayloadLength)
	pkt.Payload[0] = 1
	copy(pkt.Payload[g.SphinxPlaintextHeaderLength:], surb)
	pkt.Recipient = &commands.Recipient{}
	copy(pkt.Recipient.ID[:], "echo")
	now := time.Now()
	pkt.Delay = delay
	pkt.RecvAt = now
	pkt.DispatchAt = now
	return pkt
}

func newTestServiceNode(t *testing.T, debug config.Debug) (*serviceNode, *serviceGlue) {
	g := newServiceGlue(t, debug)
	sn, err := New(g)
	require.NoError(t, err)
	t.Cleanup(sn.Halt)
	return sn.(*serviceNode), g
}

func TestServiceNodeHoldsKaetzchenRequestUntilDelay(t *testing.T) {
	sn, g := newTestServiceNode(t, config.Debug{})

	const delay = 400 * time.Millisecond
	pkt := echoRequest(t, g.cfg.SphinxGeometry, delay)
	recvAt := pkt.RecvAt
	sn.OnPacket(pkt)

	select {
	case <-g.sched.ch:
		t.Fatal("echo replied before the request's delay passed")
	case <-time.After(delay / 2):
	}
	select {
	case r := <-g.sched.ch:
		require.GreaterOrEqual(t, r.at.Sub(recvAt), delay)
		require.Less(t, r.pkt.Delay, delay/2)
	case <-time.After(5 * time.Second):
		t.Fatal("no echo reply")
	}
}

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
	require.NotNil(t, sn.preDelay)
	require.Equal(t, defaultPreDelayQueueSize, sn.preDelay.maxLen)

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

func TestServiceNodeDisabledPreDelayRepliesAtOnce(t *testing.T) {
	sn, g := newTestServiceNode(t, config.Debug{DisableServicePreDelay: true})
	require.Nil(t, sn.preDelay)

	const delay = 2 * time.Second
	pkt := echoRequest(t, g.cfg.SphinxGeometry, delay)
	recvAt := pkt.RecvAt
	sn.OnPacket(pkt)

	select {
	case r := <-g.sched.ch:
		require.Less(t, r.at.Sub(recvAt), delay/2)
		require.Greater(t, r.pkt.Delay, delay/2)
	case <-time.After(5 * time.Second):
		t.Fatal("no echo reply")
	}
}

func sendBehindMarker(t *testing.T, sn *serviceNode, g *serviceGlue, delay time.Duration) {
	t.Helper()
	sn.OnPacket(echoRequest(t, g.cfg.SphinxGeometry, delay))
	sn.OnPacket(echoRequest(t, g.cfg.SphinxGeometry, 0))
	select {
	case <-g.sched.ch:
	case <-time.After(5 * time.Second):
		t.Fatal("no echo reply to the zero delay marker")
	}
}

func TestServiceNodeDropsRequestOverFallback(t *testing.T) {
	sn, g := newTestServiceNode(t, config.Debug{MixMaxDelayFallback: 100})

	sendBehindMarker(t, sn, g, time.Hour)
	require.Zero(t, sn.preDelay.len(), "a request over the fallback was held before a consensus")
	sendBehindMarker(t, sn, g, 10*time.Second)
	require.Zero(t, sn.preDelay.len(), "a request over the fallback was held before a consensus")
}

func TestServiceNodeConsensusCapReplacesFallback(t *testing.T) {
	sn, g := newTestServiceNode(t, config.Debug{MixMaxDelayFallback: 100})
	sn.OnNewMixMaxDelay(60000)

	sendBehindMarker(t, sn, g, 10*time.Second)
	require.Equal(t, 1, sn.preDelay.len())
	sendBehindMarker(t, sn, g, 61*time.Second)
	require.Equal(t, 1, sn.preDelay.len(), "a request over the consensus cap was held")

	sn.OnNewMixMaxDelay(0)
	sendBehindMarker(t, sn, g, time.Second)
	require.Equal(t, 1, sn.preDelay.len(), "a request over the fallback was held after a zero consensus value")
}

func TestServiceNodeDropsStaleRequestBeforeHolding(t *testing.T) {
	sn, g := newTestServiceNode(t, config.Debug{})

	pkt := echoRequest(t, g.cfg.SphinxGeometry, 0)
	pkt.DispatchAt = pkt.DispatchAt.Add(-2 * time.Second)
	sn.OnPacket(pkt)

	select {
	case <-g.sched.ch:
		t.Fatal("a request past the service dwell time was answered")
	case <-time.After(300 * time.Millisecond):
	}
	require.Zero(t, sn.preDelay.len())
}

func TestServiceNodePreDelayQueueSizeBoundsHeldRequests(t *testing.T) {
	sn, g := newTestServiceNode(t, config.Debug{ServicePreDelayQueueSize: 1})
	require.Equal(t, 1, sn.preDelay.maxLen)

	sn.OnPacket(echoRequest(t, g.cfg.SphinxGeometry, time.Hour))
	sn.OnPacket(echoRequest(t, g.cfg.SphinxGeometry, time.Hour))
	time.Sleep(200 * time.Millisecond)
	require.Equal(t, 1, sn.preDelay.len())
}

func TestDropDelayedDisposes(t *testing.T) {
	g := geo.GeometryFromUserForwardPayloadLength(ecdh.Scheme(rand.Reader), 2000, true, 5)
	pkt := echoRequest(t, g, 0)
	dropDelayed(pkt)
	require.Nil(t, pkt.Payload)
	require.Nil(t, pkt.Recipient)
}

func TestReleaseDelayedHandsOffToWorker(t *testing.T) {
	p := &serviceNode{readyCh: make(chan *packet.Packet, 1)}
	pkt := &packet.Packet{ID: 7}
	p.releaseDelayed(pkt)
	require.Same(t, pkt, <-p.readyCh)
}

func TestReleaseDelayedAfterHaltDisposes(t *testing.T) {
	g := geo.GeometryFromUserForwardPayloadLength(ecdh.Scheme(rand.Reader), 2000, true, 5)
	p := &serviceNode{readyCh: make(chan *packet.Packet)}
	p.Worker.Halt()
	pkt := echoRequest(t, g, 0)
	p.releaseDelayed(pkt)
	require.Nil(t, pkt.Payload)
	require.Nil(t, pkt.Recipient)
}

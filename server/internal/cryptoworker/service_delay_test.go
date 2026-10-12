// SPDX-License-Identifier: AGPL-3.0-only

package cryptoworker

import (
	"crypto/rand"
	"testing"
	"time"

	"github.com/katzenpost/hpqc/nike/schemes"
	"github.com/katzenpost/hpqc/nike/x25519"
	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/sphinx"
	"github.com/katzenpost/katzenpost/core/sphinx/commands"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/katzenpost/katzenpost/server/config"
	"github.com/katzenpost/katzenpost/server/internal/mixkeys"
	"github.com/katzenpost/katzenpost/server/internal/packet"
)

type captureService struct {
	pkt *packet.Packet
}

func (s *captureService) Halt()                     {}
func (s *captureService) OnPacket(p *packet.Packet) { s.pkt = p }
func (s *captureService) OnNewMixMaxDelay(uint64)   {}
func (s *captureService) KaetzchenForPKI() (map[string]map[string]interface{}, map[string]map[string]interface{}, error) {
	return nil, nil, nil
}

func TestServiceNodeGetsTheTerminalHopDelay(t *testing.T) {
	const wantMs = 1500
	mygeo := geo.GeometryFromUserForwardPayloadLength(x25519.Scheme(rand.Reader), 2000, true, 5)
	cfg := &config.Config{
		SphinxGeometry: mygeo,
		Server:         &config.Server{IsServiceNode: true},
		Logging:        &config.Logging{},
		ServiceNode:    &config.ServiceNode{},
		PKI:            &config.PKI{},
		Debug:          &config.Debug{NumKaetzchenWorkers: 1, KaetzchenDelay: 300},
	}
	goo := newTestGoo(t)
	goo.s.cfg = cfg
	svc := &captureService{}
	goo.s.service = svc

	keys, err := mixkeys.NewMixKeys(goo, mygeo)
	require.NoError(t, err)
	goo.s.mixKeys = keys
	epoch, _, _ := epochtime.Now()
	blob, ok := keys.Get(epoch)
	require.True(t, ok)
	mynike := schemes.ByName(mygeo.NIKEName)
	myPub, err := mynike.UnmarshalBinaryPublicKey(blob)
	require.NoError(t, err)

	nodes := make([]*nodeParams, mygeo.NrHops)
	for i := 0; i < mygeo.NrHops-1; i++ {
		nodes[i] = newNikeNode(t, mynike)
	}
	me := &nodeParams{publicKey: myPub}
	_, err = rand.Read(me.id[:])
	require.NoError(t, err)
	nodes[mygeo.NrHops-1] = me

	path := make([]*sphinx.PathHop, mygeo.NrHops)
	for i := range path {
		path[i] = new(sphinx.PathHop)
		copy(path[i].ID[:], nodes[i].id[:])
		path[i].NIKEPublicKey = nodes[i].publicKey
		path[i].Commands = append(path[i].Commands, &commands.NodeDelay{Delay: uint32(100 + i)})
		if i == mygeo.NrHops-1 {
			path[i].Commands[0] = &commands.NodeDelay{Delay: wantMs}
			recip := new(commands.Recipient)
			copy(recip.ID[:], []byte("echo"))
			path[i].Commands = append(path[i].Commands, recip)
		}
	}
	mysphinx, err := sphinx.FromGeometry(mygeo)
	require.NoError(t, err)
	raw, err := mysphinx.NewPacket(rand.Reader, path, make([]byte, mygeo.ForwardPayloadLength))
	require.NoError(t, err)
	for i := 0; i < mygeo.NrHops-1; i++ {
		_, _, _, err := mysphinx.Unwrap(nodes[i].privateKey, raw)
		require.NoError(t, err)
	}

	w := New(goo, make(chan interface{}), 1)
	pkt, err := packet.New(raw, mygeo)
	require.NoError(t, err)
	pkt.RecvAt = time.Now()
	require.NoError(t, w.doUnwrap(pkt))
	require.NotNil(t, pkt.NodeDelay)
	require.EqualValues(t, wantMs, pkt.NodeDelay.Delay)

	w.routePacket(pkt, time.Now())

	require.Same(t, pkt, svc.pkt, "request was not handed to the service node")
	require.Equal(t, wantMs*time.Millisecond, pkt.Delay, "the terminal-hop delay was not carried into pkt.Delay")
}

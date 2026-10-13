// SPDX-License-Identifier: AGPL-3.0-only

//go:build !noprometheus

package service

import (
	"crypto/rand"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"

	ecdh "github.com/katzenpost/hpqc/nike/x25519"

	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/katzenpost/katzenpost/server/config"
	"github.com/katzenpost/katzenpost/server/internal/glue"
	"github.com/katzenpost/katzenpost/server/internal/instrument"
	"github.com/katzenpost/katzenpost/server/internal/packet"
)

type gaugeGlue struct {
	glue.Glue
	cfg *config.Config
	log *log.Backend
}

func (g *gaugeGlue) Config() *config.Config   { return g.cfg }
func (g *gaugeGlue) LogBackend() *log.Backend { return g.log }

func TestWorkerReportsChannelUsage(t *testing.T) {
	logBackend, err := log.New("", "DEBUG", false)
	require.NoError(t, err)
	g := &gaugeGlue{
		log: logBackend,
		cfg: &config.Config{Server: &config.Server{}, Debug: &config.Debug{ServiceDelay: 10}},
	}
	func() {
		defer func() { recover() }()
		instrument.StartPrometheusListener(g)
	}()

	p := &serviceNode{glue: g, log: logBackend.GetLogger("gauge test"), ch: make(chan interface{}, 4)}
	sg := geo.GeometryFromUserForwardPayloadLength(ecdh.Scheme(rand.Reader), 2000, true, 5)
	for i := 0; i < 3; i++ {
		pkt, err := packet.New(make([]byte, sg.PacketLength), sg)
		require.NoError(t, err)
		pkt.DispatchAt = time.Now().Add(-time.Hour)
		p.ch <- pkt
	}
	p.Go(p.worker)
	defer p.Worker.Halt()
	require.Eventually(t, func() bool {
		_, peak, _ := instrument.ChannelGauge("service_incoming")
		return peak == 2
	}, 5*time.Second, 10*time.Millisecond)
}

func droppedByReason(t *testing.T, reason string) float64 {
	families, err := prometheus.DefaultGatherer.Gather()
	require.NoError(t, err)
	for _, f := range families {
		if f.GetName() != "katzenpost_dropped_reason_total" {
			continue
		}
		for _, m := range f.GetMetric() {
			if m.GetLabel()[0].GetValue() == reason {
				return m.GetCounter().GetValue()
			}
		}
	}
	return 0
}

func TestServiceNodeHaltIsNotCountedAsPreDelayOverflow(t *testing.T) {
	sn, g := newIdleServiceNode(t)
	func() {
		defer func() { recover() }()
		instrument.StartPrometheusListener(g)
	}()
	before := droppedByReason(t, "service_predelay_overflow")
	pkt := echoRequest(t, g.cfg.SphinxGeometry, time.Second)
	require.True(t, sn.preDelay.push(pkt))

	sn.Halt()

	require.Equal(t, before, droppedByReason(t, "service_predelay_overflow"))
	require.Nil(t, pkt.Payload)
	require.Nil(t, pkt.Recipient)
}

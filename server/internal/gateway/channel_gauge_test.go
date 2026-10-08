// SPDX-License-Identifier: AGPL-3.0-only

//go:build !noprometheus

package gateway

import (
	"crypto/rand"
	"testing"
	"time"

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
		cfg: &config.Config{Server: &config.Server{}, Debug: &config.Debug{GatewayDelay: 10}},
	}
	func() {
		defer func() { recover() }()
		instrument.StartPrometheusListener(g)
	}()

	p := &gateway{glue: g, log: logBackend.GetLogger("gauge test"), ch: make(chan interface{}, 4)}
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
		_, peak, _ := instrument.ChannelGauge("gateway_incoming")
		return peak == 2
	}, 5*time.Second, 10*time.Millisecond)
}

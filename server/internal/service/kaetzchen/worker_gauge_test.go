// SPDX-License-Identifier: AGPL-3.0-only

//go:build !noprometheus

package kaetzchen

import (
	"crypto/rand"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"

	ecdh "github.com/katzenpost/hpqc/nike/x25519"
	sConstants "github.com/katzenpost/katzenpost/core/sphinx/constants"

	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/katzenpost/katzenpost/server/cborplugin"
	"github.com/katzenpost/katzenpost/server/internal/instrument"
	"github.com/katzenpost/katzenpost/server/internal/packet"
)

func gaugeReported(name string) bool {
	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		return false
	}
	for _, f := range families {
		if f.GetName() != "katzenpost_channel_usage" {
			continue
		}
		for _, m := range f.GetMetric() {
			if m.GetLabel()[0].GetValue() == name {
				return true
			}
		}
	}
	return false
}

func stalePacket(t *testing.T) *packet.Packet {
	g := geo.GeometryFromUserForwardPayloadLength(ecdh.Scheme(rand.Reader), 2000, true, 5)
	pkt, err := packet.New(make([]byte, g.PacketLength), g)
	require.NoError(t, err)
	pkt.DispatchAt = time.Now().Add(-time.Hour)
	return pkt
}

func startMetrics(logBackend *log.Backend) {
	defer func() { recover() }()
	instrument.StartPrometheusListener(getGlue(logBackend, nil, nil, nil))
}

func TestWorkersReportChannelUsage(t *testing.T) {
	logBackend, err := log.New("", "DEBUG", false)
	require.NoError(t, err)
	startMetrics(logBackend)

	k := &KaetzchenWorker{
		glue:      getGlue(logBackend, nil, nil, nil),
		log:       logBackend.GetLogger("gauge test"),
		ch:        make(chan interface{}, 4),
		kaetzchen: make(map[[sConstants.RecipientIDLength]byte]Kaetzchen),
	}
	k.Go(k.worker)
	defer k.Halt()
	k.ch <- stalePacket(t)
	require.Eventually(t, func() bool { return gaugeReported("kaetzchen_incoming") }, 5*time.Second, 10*time.Millisecond)

	var recipient [sConstants.RecipientIDLength]byte
	copy(recipient[:], "+gauge")
	c := &CBORPluginWorker{
		glue:        getGlue(logBackend, nil, nil, nil),
		log:         logBackend.GetLogger("gauge test"),
		pluginChans: PluginChans{recipient: make(chan interface{}, 4)},
	}
	client := cborplugin.NewClient(logBackend, "gauge", "+gauge", nil)
	c.Go(func() { c.worker(recipient, client) })
	defer c.Halt()
	c.pluginChans[recipient] <- stalePacket(t)
	require.Eventually(t, func() bool { return gaugeReported("cbor_plugin_gauge") }, 5*time.Second, 10*time.Millisecond)
}

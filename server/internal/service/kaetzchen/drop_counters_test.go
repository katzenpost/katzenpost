// SPDX-License-Identifier: AGPL-3.0-only

//go:build !noprometheus

package kaetzchen

import (
	"crypto/rand"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"

	ecdh "github.com/katzenpost/hpqc/nike/x25519"

	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/katzenpost/katzenpost/server/cborplugin"
	"github.com/katzenpost/katzenpost/server/internal/instrument"
)

var registerMetrics sync.Once

func dropCounters(t *testing.T, capability string) (requests, responses float64) {
	families, err := prometheus.DefaultGatherer.Gather()
	require.NoError(t, err)
	for _, f := range families {
		for _, m := range f.GetMetric() {
			switch f.GetName() {
			case "katzenpost_kaetzchen_dropped_requests_total":
				requests = m.GetCounter().GetValue()
			case "katzenpost_kaetzchen_dropped_responses_total":
				if m.GetLabel()[0].GetValue() == capability {
					responses = m.GetCounter().GetValue()
				}
			}
		}
	}
	return requests, responses
}

func TestSendworkerDropCounters(t *testing.T) {
	logBackend, err := log.New("", "DEBUG", false)
	require.NoError(t, err)
	registerMetrics.Do(func() { instrument.StartPrometheusListener(getGlue(logBackend, nil, nil, nil)) })

	g := geo.GeometryFromUserForwardPayloadLength(ecdh.Scheme(rand.Reader), 2000, true, 5)
	badNIKE := *g
	badNIKE.NIKEName = "no-such-nike"

	cases := []struct {
		name         string
		geo          *geo.Geometry
		cmd          cborplugin.Command
		wantRequests float64
	}{
		{"too long", g, &cborplugin.Response{Payload: make([]byte, g.UserForwardPayloadLength+1)}, 1},
		{"surb reply failed", &badNIKE, &cborplugin.Response{SURB: make([]byte, g.SURBLength), Payload: []byte("hi")}, 0},
		{"unknown type", g, &cborplugin.Request{}, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			capability := "drop-" + tc.name
			client := cborplugin.NewClient(logBackend, capability, "", nil)
			k := &CBORPluginWorker{geo: tc.geo, log: logBackend.GetLogger("drop test")}
			go k.sendworker(client)
			defer k.Halt()

			requests0, responses0 := dropCounters(t, capability)
			client.ReadChan() <- tc.cmd
			require.Eventually(t, func() bool {
				_, responses := dropCounters(t, capability)
				return responses == responses0+1
			}, 5*time.Second, 10*time.Millisecond)
			requests, _ := dropCounters(t, capability)
			require.Equal(t, requests0+tc.wantRequests, requests)
		})
	}
}

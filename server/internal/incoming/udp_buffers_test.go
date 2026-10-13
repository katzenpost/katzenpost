// SPDX-License-Identifier: AGPL-3.0-only

//go:build !noprometheus && linux

package incoming

import (
	"os"
	"testing"

	"github.com/katzenpost/hpqc/sign"
	signSchemes "github.com/katzenpost/hpqc/sign/schemes"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/quic/common"
	"github.com/katzenpost/katzenpost/server/internal/instrument"
)

type quicCapGlue struct {
	*capGlue
	identityKey sign.PrivateKey
	quicKeys    *common.EpochKeys
}

func (g *quicCapGlue) IdentityKey() sign.PrivateKey { return g.identityKey }
func (g *quicCapGlue) QUICKeys() *common.EpochKeys  { return g.quicKeys }

func gathered(t *testing.T, name string) bool {
	families, err := prometheus.DefaultGatherer.Gather()
	require.NoError(t, err)
	for _, f := range families {
		if f.GetName() == name {
			return true
		}
	}
	return false
}

func TestQUICListenerExportsUDPBuffers(t *testing.T) {
	incomingSample("katzenpost_links_established_total", "quic")
	_, identityKey, err := signSchemes.ByName(testSchemeName).GenerateKey()
	require.NoError(t, err)
	quicKeys, err := common.NewEpochKeys(t.TempDir(), common.CurrentEpoch)
	require.NoError(t, err)
	g := &quicCapGlue{capGlue: newCapGlue(t), identityKey: identityKey, quicKeys: quicKeys}
	gl, err := New(g, make(chan interface{}), 0, "quic://127.0.0.1:0", nil, nil)
	require.NoError(t, err)
	defer gl.Halt()
	address := gl.(*listener).l.Addr().String()
	require.Positive(t, instrument.LinkSample("katzenpost_quic_udp_receive_buffer_bytes", map[string]string{"address": address}))
	require.Positive(t, instrument.LinkSample("katzenpost_quic_udp_send_buffer_bytes", map[string]string{"address": address}))
	if _, err := os.Stat("/proc/net/snmp"); err == nil {
		require.True(t, gathered(t, "katzenpost_udp_receive_buffer_errors_total"))
		require.True(t, gathered(t, "katzenpost_udp_send_buffer_errors_total"))
	}
}

// SPDX-License-Identifier: AGPL-3.0-only

package client

import (
	"bytes"
	"encoding/hex"
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	kempem "github.com/katzenpost/hpqc/kem/pem"
	kemSchemes "github.com/katzenpost/hpqc/kem/schemes"
	signpem "github.com/katzenpost/hpqc/sign/pem"
	signSchemes "github.com/katzenpost/hpqc/sign/schemes"

	"github.com/katzenpost/katzenpost/client/config"
	cpki "github.com/katzenpost/katzenpost/core/pki"
)

func pinnedGatewayConnection(t *testing.T, addresses ...string) (*connection, *net.UDPConn) {
	t.Helper()
	return gatewayFromClientTOML(t, hex.EncodeToString(bytes.Repeat([]byte{2}, cpki.QUICKeyHashSize)), addresses...)
}

func gatewayFromClientTOML(t *testing.T, quicKeyHash string, addresses ...string) (*connection, *net.UDPConn) {
	t.Helper()
	conn, udp := newGatewayTestConnection(t, &config.UpstreamProxy{})
	idPub, _, err := signSchemes.ByName(testSchemeName).GenerateKey()
	require.NoError(t, err)
	linkPub, _, err := kemSchemes.ByName("xwing").GenerateKeyPair()
	require.NoError(t, err)
	addrs := []interface{}{"quic://" + udp.LocalAddr().String()}
	for _, a := range addresses {
		addrs = append(addrs, a)
	}
	entry := map[string]interface{}{
		"Name":               "gateway1",
		"PKISignatureScheme": testSchemeName,
		"IdentityKey":        signpem.ToPublicPEMString(idPub),
		"WireKEMScheme":      "xwing",
		"LinkKey":            kempem.ToPublicPEMString(linkPub),
		"Addresses":          addrs,
	}
	if quicKeyHash != "" {
		entry["QUICKeyHash"] = quicKeyHash
	}
	gw := new(config.Gateway)
	require.NoError(t, gw.UnmarshalTOML(entry))
	conn.client.cfg.PinnedGateways.Gateways = []*config.Gateway{gw}
	conn.client.cfg.PreferedTransports = []string{cpki.TransportQUIC, cpki.TransportTCP}
	conn.descriptor = nil
	conn.pkiEpoch = 0
	return conn, udp
}

func TestFirstDialToAPinnedGatewayIsPinnedQUIC(t *testing.T) {
	conn, udp := pinnedGatewayConnection(t)
	startConnect(t, conn)
	require.True(t, receivesUDP(udp, 5*time.Second), "a client without a consensus did not dial its pinned gateway over pinned quic")
}

func TestPinnedGatewayFallsBackToTCPWhenUDPFails(t *testing.T) {
	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { tcp.Close() })
	accepted := make(chan struct{})
	go func() {
		c, err := tcp.Accept()
		if err == nil {
			c.Close()
			close(accepted)
		}
	}()
	conn, udp := pinnedGatewayConnection(t, "tcp://"+tcp.Addr().String())
	startConnect(t, conn)
	require.True(t, receivesUDP(udp, 5*time.Second), "the client did not try pinned quic first")
	select {
	case <-accepted:
	case <-time.After(30 * time.Second):
		t.Fatal("the client did not fall back to tcp after its quic dial got no answer")
	}
}

func TestDefaultClientReachesAnUnpinnedQUICGatewayOverTCP(t *testing.T) {
	tcp, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { tcp.Close() })
	accepted := make(chan struct{})
	go func() {
		c, err := tcp.Accept()
		if err == nil {
			c.Close()
			close(accepted)
		}
	}()
	conn, udp := gatewayFromClientTOML(t, "", "tcp://"+tcp.Addr().String())
	conn.client.cfg.PreferedTransports = nil
	require.NoError(t, conn.client.cfg.FixupAndValidate())
	startConnect(t, conn)
	select {
	case <-accepted:
	case <-time.After(10 * time.Second):
		t.Fatal("a client without quic did not reach its gateway over tcp")
	}
	require.False(t, receivesUDP(udp, time.Second), "a client without quic dialed its gateway over quic")
}

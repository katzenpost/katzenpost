// SPDX-License-Identifier: AGPL-3.0-only

//go:build !noprometheus

package outgoing

import (
	"net"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/hash"
	"github.com/katzenpost/hpqc/rand"
	signSchemes "github.com/katzenpost/hpqc/sign/schemes"

	"github.com/katzenpost/katzenpost/core/log"
	cpki "github.com/katzenpost/katzenpost/core/pki"
	sConstants "github.com/katzenpost/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/katzenpost/quic/common"
	"github.com/katzenpost/katzenpost/server/config"
)

func refusedTCPAddr(t *testing.T) string {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := "tcp://" + l.Addr().String()
	l.Close()
	return addr
}

func dialMismatchedPeer(t *testing.T, opts *common.Options, until func() bool) {
	quicPeer := listenQUICPeer(t)
	wrong := make([]byte, 32)
	_, err := rand.Reader.Read(wrong)
	require.NoError(t, err)
	scheme := signSchemes.ByName(testSchemeName)
	idPub, _, err := scheme.GenerateKey()
	require.NoError(t, err)
	_, link, err := benchKEMScheme.GenerateKeyPair()
	require.NoError(t, err)
	peerID, _, err := scheme.GenerateKey()
	require.NoError(t, err)
	peerLinkPub, _, err := benchKEMScheme.GenerateKeyPair()
	require.NoError(t, err)
	peerIDBlob, err := peerID.MarshalBinary()
	require.NoError(t, err)
	peerLinkBlob, err := peerLinkPub.MarshalBinary()
	require.NoError(t, err)
	backend, err := log.New("", "ERROR", false)
	require.NoError(t, err)
	g := &boundaryGlue{
		cfg: &config.Config{
			Server: &config.Server{InternalTransports: []string{cpki.TransportQUIC, cpki.TransportTCPv4}},
			Debug:  &config.Debug{HandshakeTimeout: 5000, ConnectTimeout: 5000, ReauthInterval: int(time.Hour / time.Millisecond), SendSlack: int(time.Hour / time.Millisecond)},
			QUIC:   opts,
		},
		backend: backend,
		idPub:   idPub,
		link:    link,
		pki:     &boundaryPKI{},
	}
	co := &connector{
		glue:       g,
		log:        backend.GetLogger("connector"),
		conns:      make(map[[sConstants.NodeIDLength]byte]*outgoingConn),
		closeAllCh: make(chan interface{}),
	}
	desc := &cpki.MixDescriptor{
		Name:        "peer",
		IdentityKey: peerIDBlob,
		LinkKey:     peerLinkBlob,
		Addresses: map[string][]string{
			cpki.TransportQUIC:  {quicPeer.addr},
			cpki.TransportTCPv4: {refusedTCPAddr(t)},
		},
		QUICKeyHash: wrong,
	}
	c := newOutgoingConn(co, desc, benchGeometry, benchKEMScheme)
	c.retryDelay = -time.Hour
	co.Lock()
	co.conns[hash.Sum256(peerIDBlob)] = c
	co.Unlock()
	co.closeAllWg.Add(1)
	done := make(chan struct{})
	go func() {
		c.worker()
		close(done)
	}()
	require.Eventually(t, until, 20*time.Second, 10*time.Millisecond)
	close(co.closeAllCh)
	<-done
}

func pinMismatchSamples() (mismatches, tcpDialFailures func() float64) {
	return func() float64 { return linkSample("katzenpost_quic_dials_total", "result", "mismatch") },
		func() float64 {
			return linkSample("katzenpost_link_failures_total", "transport", "tcp", "direction", "outgoing", "reason", "dial")
		}
}

func TestOutgoingPinMismatchFallsBackToTCPForTheEpoch(t *testing.T) {
	mismatches, tcpDialFailures := pinMismatchSamples()
	beforeMismatches, beforeTCP := mismatches(), tcpDialFailures()
	dialMismatchedPeer(t, nil, func() bool { return tcpDialFailures() >= beforeTCP+3 })
	require.Equal(t, beforeMismatches+1, mismatches(), "a peer that failed its pin this epoch was dialed over quic again")
}

func TestOutgoingPinMismatchStrictKeepsThePeerOffTCP(t *testing.T) {
	mismatches, tcpDialFailures := pinMismatchSamples()
	beforeMismatches, beforeTCP := mismatches(), tcpDialFailures()
	dialMismatchedPeer(t, &common.Options{PinMismatch: common.PinMismatchStrict}, func() bool { return mismatches() >= beforeMismatches+3 })
	require.Equal(t, beforeTCP, tcpDialFailures(), "a strict pin mismatch fell back to tcp")
}

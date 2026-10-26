// SPDX-License-Identifier: AGPL-3.0-only

//go:build !noprometheus

package outgoing

import (
	"net"
	"sync"
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
	"github.com/katzenpost/katzenpost/server/internal/instrument"
)

type linkPeer struct {
	listener    net.Listener
	addr        string
	quicKeyHash []byte
}

var linkMetricsOnce sync.Once

func linkSample(name string, labels ...string) float64 {
	linkMetricsOnce.Do(func() {
		defer func() { recover() }()
		instrument.StartPrometheusListener(&boundaryGlue{cfg: &config.Config{Server: &config.Server{}}})
	})
	m := make(map[string]string)
	for i := 0; i+1 < len(labels); i += 2 {
		m[labels[i]] = labels[i+1]
	}
	return instrument.LinkSample(name, m)
}

func listenQUICPeer(t *testing.T) linkPeer {
	_, identityPrivateKey, err := signSchemes.ByName(testSchemeName).GenerateKey()
	require.NoError(t, err)
	keys, err := common.NewEpochKeys(t.TempDir(), common.CurrentEpoch, nil)
	require.NoError(t, err)
	l, err := common.ListenWithEpochKeys("127.0.0.1:0", identityPrivateKey, keys, nil)
	require.NoError(t, err)
	t.Cleanup(func() { l.Close() })
	hashes, err := keys.Hashes(common.CurrentEpoch())
	require.NoError(t, err)
	return linkPeer{listener: l, addr: "quic://" + l.Addr().String(), quicKeyHash: hashes}
}

func listenTCPPeer(t *testing.T) linkPeer {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { l.Close() })
	return linkPeer{listener: l, addr: "tcp://" + l.Addr().String()}
}

func dialLinkPeer(t *testing.T, peer linkPeer, quicKeyHash []byte, serve bool, until func() bool) {
	scheme := signSchemes.ByName(testSchemeName)
	idPub, _, err := scheme.GenerateKey()
	require.NoError(t, err)
	_, link, err := benchKEMScheme.GenerateKeyPair()
	require.NoError(t, err)
	peerID, _, err := scheme.GenerateKey()
	require.NoError(t, err)
	peerLinkPub, peerLink, err := benchKEMScheme.GenerateKeyPair()
	require.NoError(t, err)
	peerIDBlob, err := peerID.MarshalBinary()
	require.NoError(t, err)
	peerLinkBlob, err := peerLinkPub.MarshalBinary()
	require.NoError(t, err)

	if serve {
		go servePackets(t, peer.listener, peerID, peerLink, make(chan struct{}, 1))
	} else {
		go func() {
			c, err := peer.listener.Accept()
			if err == nil {
				c.Close()
			}
		}()
	}

	backend, err := log.New("", "ERROR", false)
	require.NoError(t, err)
	g := &boundaryGlue{
		cfg: &config.Config{
			Server: &config.Server{},
			Debug:  &config.Debug{HandshakeTimeout: 5000, ConnectTimeout: 5000, ReauthInterval: int(time.Hour / time.Millisecond), SendSlack: int(time.Hour / time.Millisecond)},
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
		Addresses:   map[string][]string{cpki.TransportTCPv4: {peer.addr}},
		QUICKeyHash: quicKeyHash,
	}
	c := newOutgoingConn(co, desc, benchGeometry, benchKEMScheme)
	co.Lock()
	co.conns[hash.Sum256(peerIDBlob)] = c
	co.Unlock()
	co.closeAllWg.Add(1)
	done := make(chan struct{})
	go func() {
		c.worker()
		close(done)
	}()
	require.Eventually(t, until, 10*time.Second, 10*time.Millisecond)
	close(co.closeAllCh)
	<-done
}

func TestOutgoingTCPLinkCountsItsSetup(t *testing.T) {
	links := func() float64 {
		return linkSample("katzenpost_links_established_total", "transport", "tcp", "direction", "outgoing")
	}
	setups := func() float64 {
		return linkSample("katzenpost_link_handshake_duration_seconds", "transport", "tcp", "direction", "outgoing")
	}
	quicLinks := linkSample("katzenpost_links_established_total", "transport", "quic")
	beforeLinks, beforeSetups := links(), setups()
	dialLinkPeer(t, listenTCPPeer(t), nil, true, func() bool { return links() > beforeLinks })
	require.Equal(t, beforeLinks+1, links())
	require.Equal(t, beforeSetups+1, setups())
	require.Equal(t, quicLinks, linkSample("katzenpost_links_established_total", "transport", "quic"))
}

func TestOutgoingTCPHandshakeFailureCounts(t *testing.T) {
	failures := func() float64 {
		return linkSample("katzenpost_link_failures_total", "transport", "tcp", "direction", "outgoing", "reason", "handshake")
	}
	links := linkSample("katzenpost_links_established_total", "transport", "tcp", "direction", "outgoing")
	before := failures()
	dialLinkPeer(t, listenTCPPeer(t), nil, false, func() bool { return failures() > before })
	require.Equal(t, before+1, failures())
	require.Equal(t, links, linkSample("katzenpost_links_established_total", "transport", "tcp", "direction", "outgoing"))
}

func TestOutgoingTCPDialFailureCounts(t *testing.T) {
	failures := func() float64 {
		return linkSample("katzenpost_link_failures_total", "transport", "tcp", "direction", "outgoing", "reason", "dial")
	}
	peer := listenTCPPeer(t)
	peer.listener.Close()
	before := failures()
	dialLinkPeer(t, peer, nil, false, func() bool { return failures() > before })
	require.Equal(t, before+1, failures())
}

func TestOutgoingQUICPinnedLinkCounts(t *testing.T) {
	pinned := func() float64 { return linkSample("katzenpost_quic_dials_total", "result", "pinned") }
	links := func() float64 {
		return linkSample("katzenpost_links_established_total", "transport", "quic", "direction", "outgoing")
	}
	setups := func() float64 {
		return linkSample("katzenpost_link_handshake_duration_seconds", "transport", "quic", "direction", "outgoing")
	}
	beforePinned, beforeLinks, beforeSetups := pinned(), links(), setups()
	peer := listenQUICPeer(t)
	dialLinkPeer(t, peer, peer.quicKeyHash, true, func() bool { return links() > beforeLinks })
	require.Equal(t, beforePinned+1, pinned())
	require.Equal(t, beforeLinks+1, links())
	require.Equal(t, beforeSetups+1, setups())
}

func TestOutgoingQUICPinMismatchCounts(t *testing.T) {
	mismatches := func() float64 { return linkSample("katzenpost_quic_dials_total", "result", "mismatch") }
	failures := func() float64 {
		return linkSample("katzenpost_link_failures_total", "transport", "quic", "direction", "outgoing", "reason", "pin_mismatch")
	}
	dialFailures := linkSample("katzenpost_link_failures_total", "transport", "quic", "reason", "dial")
	beforeMismatches, beforeFailures := mismatches(), failures()
	wrong := make([]byte, 32)
	_, err := rand.Reader.Read(wrong)
	require.NoError(t, err)
	dialLinkPeer(t, listenQUICPeer(t), wrong, false, func() bool { return failures() > beforeFailures })
	require.Equal(t, beforeMismatches+1, mismatches())
	require.Equal(t, beforeFailures+1, failures())
	require.Equal(t, dialFailures, linkSample("katzenpost_link_failures_total", "transport", "quic", "reason", "dial"))
}

// SPDX-License-Identifier: AGPL-3.0-only

package incoming

import (
	"container/list"
	"net"
	"testing"
	"time"

	"gopkg.in/op/go-logging.v1"

	"github.com/katzenpost/hpqc/kem"
	"github.com/katzenpost/hpqc/kem/schemes"
	"github.com/katzenpost/hpqc/sign"
	signSchemes "github.com/katzenpost/hpqc/sign/schemes"

	"github.com/katzenpost/katzenpost/core/connlimit"
	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/katzenpost/server/config"
	"github.com/katzenpost/katzenpost/server/internal/glue"
)

type addrConn struct {
	net.Conn
	remote net.Addr
}

func (c *addrConn) RemoteAddr() net.Addr { return c.remote }

type capGlue struct {
	glue.Glue
	cfg    *config.Config
	logBE  *log.Backend
	idPub  sign.PublicKey
	linkPk kem.PrivateKey
	pki    glue.PKI
}

func (g *capGlue) Config() *config.Config            { return g.cfg }
func (g *capGlue) LogBackend() *log.Backend          { return g.logBE }
func (g *capGlue) IdentityPublicKey() sign.PublicKey { return g.idPub }
func (g *capGlue) LinkKey() kem.PrivateKey           { return g.linkPk }
func (g *capGlue) PKI() glue.PKI                     { return g.pki }

func newCapGlue(t *testing.T) *capGlue {
	t.Helper()
	kemScheme := schemes.ByName("xwing")
	_, linkPk, err := kemScheme.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	idPub, _, err := signSchemes.ByName("Ed25519").GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	logBE, err := log.New("", "ERROR", false)
	if err != nil {
		t.Fatal(err)
	}
	return &capGlue{
		cfg: &config.Config{
			Server:         &config.Server{WireKEM: "xwing", PKISignatureScheme: "Ed25519"},
			SphinxGeometry: benchGeometry,
			Debug:          &config.Debug{HandshakeTimeout: 30000},
		},
		logBE:  logBE,
		idPub:  idPub,
		linkPk: linkPk,
		pki:    &fakePKI{usable: true},
	}
}

func tcpAddr(ip string) net.Addr { return &net.TCPAddr{IP: net.ParseIP(ip), Port: 1} }

func newCapListener(t *testing.T, limiter *connlimit.Limiter, peerSet *connlimit.PeerSet) (*listener, *gateListener) {
	t.Helper()
	gl := &gateListener{conns: make(chan net.Conn, 4), done: make(chan struct{})}
	l := &listener{
		glue:        newCapGlue(t),
		log:         logging.MustGetLogger("incoming_cap_test"),
		l:           gl,
		conns:       list.New(),
		connsByID:   make(map[[constants.RecipientIDLength]byte]*incomingConn),
		closeAllCh:  make(chan interface{}),
		connLimiter: limiter,
		peerSet:     peerSet,
	}
	return l, gl
}

func feedConn(gl *gateListener, ip string) net.Conn {
	serverConn, clientConn := net.Pipe()
	gl.conns <- &addrConn{Conn: serverConn, remote: tcpAddr(ip)}
	return clientConn
}

func expectClosed(t *testing.T, c net.Conn, msg string) {
	t.Helper()
	if err := c.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	_, err := c.Read(make([]byte, 1))
	if err == nil {
		t.Fatal(msg + ": connection was not closed")
	}
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal(msg + ": connection stayed open (timed out) but should have been refused")
	}
}

func expectAdmitted(t *testing.T, c net.Conn, msg string) {
	t.Helper()
	if err := c.SetReadDeadline(time.Now().Add(500 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	_, err := c.Read(make([]byte, 1))
	if err == nil {
		t.Fatal(msg + ": unexpected data on an admitted connection")
	}
	if ne, ok := err.(net.Error); !ok || !ne.Timeout() {
		t.Fatalf("%s: admitted connection was closed instead of proceeding: %v", msg, err)
	}
}

// TestListenerAdmitsPeerWhenClientPoolExhausted fills the client pool and
// proves the accept gate refuses a further non-peer connection while still
// admitting a connection from a known peer IP into the independent peer pool.
func TestListenerAdmitsPeerWhenClientPoolExhausted(t *testing.T) {
	limiter := connlimit.New(1, 1, 0)
	if _, ok := limiter.TryAcquire(tcpAddr("10.0.0.9"), false); !ok {
		t.Fatal("failed to pre-fill the client pool")
	}
	peerSet := connlimit.NewPeerSet()
	peerSet.Rebuild([]string{"tcp://192.0.2.1:30001"})

	l, gl := newCapListener(t, limiter, peerSet)
	go l.worker()
	defer func() {
		gl.Close()
		l.l.Close()
	}()

	clientRefused := feedConn(gl, "203.0.113.7")
	expectClosed(t, clientRefused, "non-peer over the client cap")

	peerAdmitted := feedConn(gl, "192.0.2.1")
	expectAdmitted(t, peerAdmitted, "known peer while the client pool is exhausted")
}

// TestListenerEpochSwapReclassifiesPeer proves the listener reads the live
// peer set at accept: an IP absent from the set is refused as a client while
// the client pool is full, then admitted as a peer once the set is swapped to
// include it, as the PKI worker does each epoch.
func TestListenerEpochSwapReclassifiesPeer(t *testing.T) {
	limiter := connlimit.New(1, 1, 0)
	if _, ok := limiter.TryAcquire(tcpAddr("10.0.0.9"), false); !ok {
		t.Fatal("failed to pre-fill the client pool")
	}
	peerSet := connlimit.NewPeerSet()

	l, gl := newCapListener(t, limiter, peerSet)
	go l.worker()
	defer func() {
		gl.Close()
		l.l.Close()
	}()

	before := feedConn(gl, "198.51.100.5")
	expectClosed(t, before, "unknown IP while the client pool is exhausted")

	peerSet.Rebuild([]string{"tcp://198.51.100.5:30001"})

	after := feedConn(gl, "198.51.100.5")
	expectAdmitted(t, after, "same IP after it is reclassified as a peer")
}

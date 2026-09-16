// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"sync"
	"time"

	"github.com/katzenpost/hpqc/hash"
	"github.com/katzenpost/hpqc/kem/schemes"
	"github.com/katzenpost/hpqc/rand"
	signSchemes "github.com/katzenpost/hpqc/sign/schemes"

	"github.com/katzenpost/katzenpost/authority/voting/server/config"
	"github.com/katzenpost/katzenpost/core/wire"
	"github.com/katzenpost/katzenpost/core/wire/commands"
	"github.com/katzenpost/katzenpost/core/wire/handshakeinstrument"
	"github.com/katzenpost/katzenpost/quic/common"
)

// peerConn is a persistent authenticated session to a peer authority. Its
// mutex serializes round trips so a single session is never driven by two
// goroutines at once (which would race the cipher state).
type peerConn struct {
	mu      sync.Mutex
	session *wire.Session
	conn    net.Conn

	// closeMu guards live, the underlying connection, independently of mu.
	// Shutdown closes live via closeLive without taking mu, so it can unblock a
	// send goroutine that holds mu across a wedged network write.
	closeMu sync.Mutex
	live    net.Conn
}

// setLive records the underlying connection so shutdown can close it without
// taking pc.mu. Pass nil to clear it.
func (pc *peerConn) setLive(conn net.Conn) {
	pc.closeMu.Lock()
	pc.live = conn
	pc.closeMu.Unlock()
}

// closeLive closes the underlying connection without taking pc.mu, unblocking a
// send goroutine wedged on a write while it holds pc.mu.
func (pc *peerConn) closeLive() {
	pc.closeMu.Lock()
	if pc.live != nil {
		pc.live.Close()
	}
	pc.closeMu.Unlock()
}

// closeLocked tears down the session; the caller must hold pc.mu.
func (pc *peerConn) closeLocked() {
	if pc.session != nil {
		pc.session.Close() // also closes pc.conn
	}
	pc.session = nil
	pc.conn = nil
	pc.setLive(nil)
}

// peerConnFor returns the peerConn for id, creating an empty one on first use.
func (s *state) peerConnFor(id string) *peerConn {
	s.peerConnsMu.Lock()
	defer s.peerConnsMu.Unlock()
	if s.peerConns == nil {
		s.peerConns = make(map[string]*peerConn)
	}
	pc, ok := s.peerConns[id]
	if !ok {
		pc = &peerConn{}
		s.peerConns[id] = pc
	}
	return pc
}

// closeAllPeerConns closes every cached peer session. Called at shutdown.
func (s *state) closeAllPeerConns() {
	s.peerConnsMu.Lock()
	conns := s.peerConns
	s.peerConns = make(map[string]*peerConn)
	s.peerConnsMu.Unlock()
	for _, pc := range conns {
		pc.mu.Lock()
		pc.closeLocked()
		pc.mu.Unlock()
	}
}

// closeLivePeerConns closes the underlying connection of every cached peer conn
// without taking pc.mu. Called early in shutdown so a send goroutine wedged on
// a write (which holds pc.mu) is unblocked and the daemon's goroutine drain
// does not stall on it. The full teardown still runs later via closeAllPeerConns.
func (s *state) closeLivePeerConns() {
	s.peerConnsMu.Lock()
	pcs := make([]*peerConn, 0, len(s.peerConns))
	for _, pc := range s.peerConns {
		pcs = append(pcs, pc)
	}
	s.peerConnsMu.Unlock()
	for _, pc := range pcs {
		pc.closeLive()
	}
}

// dialAndHandshakePeer dials the peer and completes the wire handshake,
// returning an established session and its connection.
func (s *state) dialAndHandshakePeer(peer *config.Authority, addrs []string) (*wire.Session, net.Conn, error) {
	dialTimeout := time.Duration(s.s.cfg.Server.DialTimeoutSec) * time.Second
	handshakeTimeout := time.Duration(s.s.cfg.Server.HandshakeTimeoutSec) * time.Second
	responseTimeout := time.Duration(s.s.cfg.Server.ResponseTimeoutSec) * time.Second

	dialFn := s.dialContextFn
	if dialFn == nil {
		dialFn = (&net.Dialer{Timeout: dialTimeout}).DialContext
	}

	var conn net.Conn
	var errs []error
	for _, a := range addrs {
		u, err := url.Parse(a)
		if err != nil {
			s.log.Debugf("peer %s: invalid URL %s: %v", peer.Identifier, a, err)
			errs = append(errs, fmt.Errorf("invalid URL %s: %w", a, err))
			continue
		}
		ctx, cancelFn := context.WithTimeout(context.Background(), dialTimeout)
		conn, err = common.DialURL(u, ctx, dialFn)
		cancelFn()
		if err == nil {
			break
		}
		s.log.Debugf("peer %s: dial %s failed: %v", peer.Identifier, a, err)
		errs = append(errs, fmt.Errorf("dial %s failed: %w", a, err))
	}
	if conn == nil {
		// Report every failure, whether an address failed to parse or to dial,
		// so a trailing parse error can no longer bury an earlier informative
		// dial failure. Fall back to the generic message only when there were no
		// addresses at all.
		if len(errs) > 0 {
			return nil, nil, fmt.Errorf("peer %s: all addresses exhausted: %w", peer.Identifier, errors.Join(errs...))
		}
		return nil, nil, fmt.Errorf("peer %s: no usable address could be dialed", peer.Identifier)
	}

	identityHash := hash.Sum256From(s.s.identityPublicKey)
	kemscheme := schemes.ByName(s.s.cfg.Server.WireKEMScheme)
	if kemscheme == nil {
		conn.Close()
		panic("kem scheme not found in registry")
	}
	cfg := &wire.SessionConfig{
		KEMScheme:          kemscheme,
		PKISignatureScheme: signSchemes.ByName(s.s.cfg.Server.PKISignatureScheme),
		Geometry:           s.geo,
		Authenticator:      s,
		AdditionalData:     identityHash[:],
		AuthenticationKey:  s.s.linkKey,
		RandomReader:       rand.Reader,
		HandshakeTimeout:   handshakeTimeout,
		ReadTimeout:        responseTimeout,
		WriteTimeout:       responseTimeout,
		MaxMessageSize:     s.s.maxMessageSize,
	}
	session, err := wire.NewPKISession(cfg, true)
	if err != nil {
		conn.Close()
		return nil, nil, err
	}

	conn.SetDeadline(time.Now().Add(handshakeTimeout))
	handshakeStart := time.Now()
	if err = session.Initialize(context.Background(), conn); err != nil {
		handshakeElapsed := time.Since(handshakeStart)
		st := "other"
		if he, ok := wire.GetHandshakeError(err); ok {
			st = string(he.State)
		} else if wire.IsNoHandshakeBytesError(err) {
			st = "premature_close"
		}
		handshakeinstrument.HandshakeFailure("outgoing", st)
		handshakeinstrument.HandshakeDuration("outgoing", "failure", handshakeElapsed)
		if he, ok := wire.GetHandshakeError(err); ok {
			he.WithPeerName(peer.Identifier)
		}
		s.log.Debugf("peer %s: handshake failure details:\n%s", peer.Identifier, wire.GetDebugError(err))
		session.Close()
		return nil, nil, err
	}
	handshakeElapsed := time.Since(handshakeStart)
	handshakeinstrument.HandshakeDuration("outgoing", "success", handshakeElapsed)
	s.log.Debugf("peer %s: Handshake completed in %v", peer.Identifier, handshakeElapsed)
	return session, conn, nil
}

// peerRoundTrip sends cmd over an established session and returns the reply.
func (s *state) peerRoundTrip(session *wire.Session, conn net.Conn, cmd commands.Command) (commands.Command, error) {
	responseTimeout := time.Duration(s.s.cfg.Server.ResponseTimeoutSec) * time.Second
	conn.SetDeadline(time.Now().Add(responseTimeout))
	if err := session.SendCommand(context.Background(), cmd); err != nil {
		return nil, err
	}
	return session.RecvCommand(context.Background())
}

// peerKeepaliveWorker keeps cached peer sessions warm with periodic NoOps so
// the responder's idle timeout does not close them between phases.
func (s *state) peerKeepaliveWorker() {
	if !s.s.cfg.Server.PersistentPeerConns {
		return
	}
	interval := time.Duration(s.s.cfg.Server.KeepaliveTimeoutSec) * time.Second / 2
	if interval <= 0 {
		return
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-s.HaltCh():
			return
		case <-t.C:
			s.sendPeerKeepalives()
		}
	}
}

// peerKeepaliveWriteTimeout bounds how long a keepalive NoOp write may block.
// The keepalive holds pc.mu across the write, so a keepalive to a TCP-stalled
// peer would delay a real send queued behind it on the same session for as long
// as the write blocks. A pre-set conn deadline does not help here: SendCommand
// re-arms its own write deadline (Session.writeTimeout, a minute by default) and
// clobbers it. SendCommand does honor an earlier context deadline, so pass a
// short one to bound the keepalive write and let a stalled keepalive release the
// lock quickly. It is a package var so a test can shorten it.
var peerKeepaliveWriteTimeout = 5 * time.Second

func (s *state) sendPeerKeepalives() {
	s.peerConnsMu.Lock()
	pcs := make([]*peerConn, 0, len(s.peerConns))
	for _, pc := range s.peerConns {
		pcs = append(pcs, pc)
	}
	s.peerConnsMu.Unlock()

	for _, pc := range pcs {
		// Keepalive is best-effort; never block real voting traffic. If a round
		// trip already holds the lock, skip this peer (the traffic keeps it warm).
		if !pc.mu.TryLock() {
			continue
		}
		if pc.session != nil {
			if err := s.keepaliveSend(pc.session); err != nil {
				pc.closeLocked()
			}
		}
		pc.mu.Unlock()
	}
}

// keepaliveSend writes a single keepalive NoOp on session, recovering from a
// panic the same way doSendCommand does so a bug in the send path drops the
// connection instead of crashing the whole authority through the keepalive
// worker goroutine.
func (s *state) keepaliveSend(session *wire.Session) (rerr error) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Errorf("recovered from panic in keepalive send: %v", r)
			rerr = fmt.Errorf("recovered from panic in keepalive send: %v", r)
		}
	}()
	ctx, cancel := context.WithTimeout(context.Background(), peerKeepaliveWriteTimeout)
	defer cancel()
	return session.SendCommand(ctx, &commands.NoOp{Cmds: session.GetCommands()})
}

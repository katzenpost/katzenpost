// SPDX-FileCopyrightText: Copyright (C) 2017  Yawning Angel.
// SPDX-License-Identifier: AGPL-3.0-only

package client

import (
	"context"
	"crypto/hmac"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/katzenpost/hpqc/hash"
	"github.com/katzenpost/hpqc/kem/pem"
	"github.com/katzenpost/hpqc/kem/schemes"
	"github.com/katzenpost/hpqc/rand"
	"gopkg.in/op/go-logging.v1"

	"github.com/katzenpost/katzenpost/client/instrument"
	cpki "github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/wire"
	"github.com/katzenpost/katzenpost/core/wire/commands"
	"github.com/katzenpost/katzenpost/core/wire/handshakeinstrument"
	"github.com/katzenpost/katzenpost/core/worker"
	"github.com/katzenpost/katzenpost/quic/common"
)

var (
	// ErrNotConnected is the error returned when an operation fails due to the
	// client not currently being connected to the Gateway.
	ErrNotConnected = errors.New("client/conn: not connected to the Gateway")

	// ErrShutdown is the error returned when the connection is closed due to
	// a call to Shutdown().
	ErrShutdown = errors.New("shutdown requested")

	defaultDialer = net.Dialer{
		KeepAlive: keepAliveInterval,
		Timeout:   connectTimeout,
	}

	keepAliveInterval = 3 * time.Minute
	connectTimeout    = 1 * time.Minute

	// readIdleTimeout bounds how long the peer reader will wait between
	// successive commands from the gateway before declaring the link
	// dead and tearing it down for reconnect. The post-handshake socket
	// otherwise has no read deadline ("client can take however long it
	// wants"), so a half-broken TCP link with no FIN/RST leaves
	// RecvCommand blocked indefinitely. The connection's pump sends a
	// RetrieveMessage every fetchDelay (3s) and the gateway replies
	// promptly under normal load, so a quiet read for more than several
	// heartbeats indicates the link, not the gateway. Fifteen seconds is
	// five RetrieveMessage cycles, leaves room for an occasional slow
	// reply, and gets us back into a redial within half a minute.
	readIdleTimeout = 15 * time.Second
)

// ConnectError is the error used to indicate that a connect attempt has failed.
type ConnectError struct {
	// Err is the original error that caused the connect attempt to fail.
	Err error
}

// Error implements the error interface.
func (e *ConnectError) Error() string {
	return fmt.Sprintf("client/conn: connect error: %v", e.Err)
}

func newConnectError(f string, a ...interface{}) error {
	return &ConnectError{Err: fmt.Errorf(f, a...)}
}

// PKIError is the error used to indicate PKI related failures.
type PKIError struct {
	// Err is the original PKI error.
	Err error
}

// Error implements the error interface.
func (e *PKIError) Error() string {
	return fmt.Sprintf("client/conn: PKI error: %v", e.Err)
}

func newPKIError(f string, a ...interface{}) error {
	return &PKIError{Err: fmt.Errorf(f, a...)}
}

// ProtocolError is the error used to indicate that the connection was closed
// due to wire protocol related reasons.
type ProtocolError struct {
	// Err is the original error that triggered connection termination.
	Err error
}

// Error implements the error interface.
func (e *ProtocolError) Error() string {
	return fmt.Sprintf("client/conn: protocol error: %v", e.Err)
}

func newProtocolError(f string, a ...interface{}) error {
	return &ProtocolError{Err: fmt.Errorf(f, a...)}
}

type connection struct {
	worker.Worker

	client *Client
	log    *logging.Logger

	pkiEpoch   uint64
	descriptor *cpki.MixDescriptor

	sendCh         chan *connSendCtx
	getConsensusCh chan *getConsensusCtx

	retryDelay int64 // used as atomic time.Duration

	isConnected atomic.Bool

	gatewayLock sync.RWMutex
	gateway     *[32]byte
	queueID     []byte

	isShutdown atomic.Bool
}

// getGateway safely returns the current gateway hash
func (c *connection) getGateway() *[32]byte {
	c.gatewayLock.RLock()
	defer c.gatewayLock.RUnlock()
	return c.gateway
}

// gatewayLabel returns a human-readable identifier for the gateway this
// connection is bound to: its configured name where known, otherwise the
// identity-key fingerprint, so connection-status logs name the peer. It is
// read from the connect worker's descriptor, which is set before any
// connection-status change is reported.
func (c *connection) gatewayLabel() string {
	if c.descriptor != nil && c.descriptor.Name != "" {
		return fmt.Sprintf("%q", c.descriptor.Name)
	}
	if gw := c.getGateway(); gw != nil {
		return fmt.Sprintf("%x", gw[:])
	}
	return "(unknown)"
}

type getConsensusCtx struct {
	replyCh chan interface{}
	epoch   uint64
	doneFn  func(error)
}

type connSendCtx struct {
	pkt    []byte
	doneFn func(error)
}

// ForceFetchPKI attempts to force client's pkiclient to wake and fetch
// consensus documents immediately.
func (c *Client) ForceFetchPKI() {
	select {
	case c.pki.forceUpdateCh <- true:
	default:
	}
}

func (c *connection) getDescriptor() error {
	// Save the previously-cached descriptor so the deferred cleanup can
	// restore it if the fresh PKI fetch fails. Otherwise a momentary
	// outage that expires the daemon's PKI cache would also wipe the
	// gateway descriptor, leaving the connect loop with no address to
	// dial. Reconnect is how PKI is refreshed in the first place, so
	// gating it on fresh PKI deadlocks.
	prev := c.descriptor
	ok := false
	defer func() {
		if !ok {
			c.pkiEpoch = 0
			c.descriptor = prev
		}
	}()

	_, doc := c.client.CurrentDocument()
	if doc == nil && c.client.cfg.CachedDocument == nil {
		c.log.Debugf("No PKI document for current epoch or cached PKI document provide.")
		n := 0
		if c.client.cfg.PinnedGateways != nil {
			n = len(c.client.cfg.PinnedGateways.Gateways)
		}
		if n == 0 {
			if prev != nil {
				// No fresh PKI and no pinned gateways: keep the
				// previously-known descriptor so doConnect can
				// retry the same gateway. A stale address is far
				// better than refusing to redial; the next
				// successful handshake refreshes PKI.
				c.log.Debugf("No fresh PKI doc; reusing prior descriptor for %v", prev.Name)
				ok = true
				return nil
			}
			return errors.New("no PinnedGateways")
		}
		gateway := c.client.cfg.PinnedGateways.Gateways[rand.NewMath().Intn(n)]
		idHash := hash.Sum256From(gateway.IdentityKey)
		c.gatewayLock.Lock()
		c.gateway = &idHash
		c.gatewayLock.Unlock()

		idkey, err := gateway.IdentityKey.MarshalBinary()
		if err != nil {
			return err
		}

		linkkey, err := gateway.LinkKey.MarshalBinary()
		if err != nil {
			return err
		}

		c.descriptor = &cpki.MixDescriptor{
			Name:          gateway.Name,
			IdentityKey:   idkey,
			LinkKey:       linkkey,
			Addresses:     addressesFromURLs(gateway.Addresses),
			IsGatewayNode: true,
		}
		ok = true
		return nil
	} else if doc == nil {
		doc = c.client.cfg.CachedDocument
	}
	if doc != nil {
		n := len(doc.GatewayNodes)
		if n == 0 {
			return errors.New("invalid PKI doc, zero Gateways")
		}
		gateway := doc.GatewayNodes[rand.NewMath().Intn(n)]
		idHash := hash.Sum256(gateway.IdentityKey)
		c.gatewayLock.Lock()
		c.gateway = &idHash
		c.gatewayLock.Unlock()
		desc, err := doc.GetGateway(gateway.Name)
		if err != nil {
			c.log.Debugf("Failed to find descriptor for Gateway: %v", err)
			return newPKIError("failed to find descriptor for Gateway: %v", err)
		}
		if !hmac.Equal(gateway.IdentityKey, desc.IdentityKey) {
			c.log.Errorf("Gateway identity key does not match pinned key: %v", desc.IdentityKey)
			return newPKIError("identity key for Gateway does not match pinned key: %v", desc.IdentityKey)
		}
		if desc != c.descriptor {
			c.log.Debugf("Descriptor for epoch %v: %+v", doc.Epoch, desc)
		}

		c.descriptor = desc
		c.pkiEpoch = doc.Epoch
		ok = true

		return nil
	}

	return errors.New("current pki doc is nil")
}

func (c *connection) connectWorker() {
	defer c.log.Debugf("Terminating connect worker.")

	dialCtx, cancelFn := context.WithCancel(context.Background())
	c.Go(func() {
		select {
		case <-c.HaltCh():
			cancelFn()
		case <-dialCtx.Done():
		}
	})

	for {
		select {
		case <-c.HaltCh():
			return
		default:
		}

		c.doConnect(dialCtx)
	}
}

func (c *connection) doConnect(dialCtx context.Context) {
	const (
		retryIncrement = 15 * time.Second
		maxRetryDelay  = 2 * time.Minute
	)

	dialFn := c.client.DialContextFn
	if dialFn == nil {
		dialFn = defaultDialer.DialContext
	}

	var connErr error
	defer func() {
		if connErr == nil {
			//panic("BUG: connErr is nil on connection teardown.")
		}

		if c.client.cfg.Callbacks != nil {
			if c.client.cfg.Callbacks.OnConnFn != nil {
				if !c.isShutdown.Load() {
					c.client.cfg.Callbacks.OnConnFn(connErr)
				}
			}
		}
	}()

	for {
		connErr = c.getDescriptor()
		if connErr != nil {
			c.log.Debugf("Aborting connect loop, descriptor no longer present.")
			return
		}
		c.log.Debugf("doConnect, got descriptor %v", c.descriptor)

		// Build the list of candidate addresses, in decreasing order of
		// preference, by transport.
		var dstAddrs []string
		transports := c.client.cfg.PreferedTransports
		if transports == nil {
			transports = cpki.ClientTransports
		}
		for _, t := range transports {
			if v, ok := c.descriptor.Addresses[t]; ok {
				dstAddrs = append(dstAddrs, v...)
			}
		}
		if len(dstAddrs) == 0 {
			c.log.Warningf("Aborting connect loop, no suitable addresses found.")
			c.descriptor = nil // Give up till the next PKI fetch.
			connErr = newConnectError("no suitable addresses found")
			return
		}

		for _, addr := range dstAddrs {
			select {
			case <-time.After(time.Duration(atomic.LoadInt64(&c.retryDelay))):
				// Back off the reconnect delay.
				atomic.AddInt64(&c.retryDelay, int64(retryIncrement))
				if atomic.LoadInt64(&c.retryDelay) > int64(maxRetryDelay) {
					atomic.StoreInt64(&c.retryDelay, int64(maxRetryDelay))
				}
			case <-c.HaltCh():
				c.log.Debugf("(Re)connection attempts cancelled.")
				connErr = ErrShutdown
				return
			}

			c.log.Debugf("Dialing: %v", addr)

			u, err := url.Parse(addr)
			if err != nil {
				c.log.Warning("invalid addr '%v'", addr)
				continue
			}

			conn, err := common.DialURL(u, dialCtx, dialFn)
			select {
			case <-c.HaltCh():
				if conn != nil {
					conn.Close()
				}
				connErr = ErrShutdown
				return
			default:
				if err != nil {
					c.log.Warningf("Failed to connect to %v: %v", addr, err)
					if c.client.cfg.Callbacks.OnConnFn != nil {
						c.client.cfg.Callbacks.OnConnFn(&ConnectError{Err: err})
					}
					continue
				}
			}
			c.log.Debugf("TCP connection established.")
			// Disable Nagle so the PQ Noise handshake's finalisation
			// NoOp does not wait on a coalesce timer; harmless on
			// non-TCP transports. Also enable TCP keepalive so the
			// kernel probes a silent peer rather than leaving us
			// blocked on a half-broken socket indefinitely; the
			// application-level read deadline below complements
			// this for cases where the kernel's probe budget is
			// generous.
			if tcpConn, ok := conn.(*net.TCPConn); ok {
				tcpConn.SetNoDelay(true)
				_ = tcpConn.SetKeepAlive(true)
				_ = tcpConn.SetKeepAlivePeriod(15 * time.Second)
			}

			// Do something with the connection.
			c.onNetConn(conn)

			// Re-iterate through the address/ports on a sucessful connect.
			c.log.Debugf("Connection terminated (onNetConn done), will reconnect.")

			// Emit a ConnectError when disconnected.
			c.onConnStatusChange(ErrNotConnected)
			break
		}
	}
}

func (c *connection) onNetConn(conn net.Conn) {
	const handshakeTimeout = 1 * time.Minute
	var err error

	defer func() {
		c.log.Debugf("connection closed.")
		conn.Close()
	}()
	_, linkKey, err := c.client.wireKEMScheme.GenerateKeyPair()
	if err != nil {
		panic(err)
	}

	// Allocate the session struct.
	userId := make([]byte, 16)
	_, err = rand.Reader.Read(userId)
	if err != nil {
		panic(err)
	}
	c.queueID = []byte(fmt.Sprintf("%x", userId))

	cfg := &wire.SessionConfig{
		KEMScheme:         c.client.wireKEMScheme,
		Geometry:          c.client.cfg.SphinxGeometry,
		Authenticator:     c,
		AdditionalData:    c.queueID,
		AuthenticationKey: linkKey,
		RandomReader:      rand.Reader,
		// The Session now enforces these itself, so the manual SetDeadline
		// dance below is gone. ReadTimeout reproduces the old sliding
		// readIdleTimeout (re-armed on every RecvCommand); the write path,
		// previously left unbounded, is now bounded by the default so a gateway
		// that stops reading cannot wedge the client's send loop forever.
		HandshakeTimeout: handshakeTimeout,
		ReadTimeout:      readIdleTimeout,
	}
	w, err := wire.NewSession(cfg, true)
	if err != nil {
		c.log.Errorf("Failed to allocate session: %v", err)
		if c.client.cfg.Callbacks.OnConnFn != nil {
			c.client.cfg.Callbacks.OnConnFn(&ConnectError{Err: err})
		}
		return
	}
	defer w.Close()

	// Bind the session to the conn, handshake, authenticate. The Session
	// enforces the handshake deadline (HandshakeTimeout) itself.
	handshakeStart := time.Now()
	if err = w.Initialize(context.Background(), conn); err != nil {
		handshakeElapsed := time.Since(handshakeStart)
		state := "other"
		if he, ok := wire.GetHandshakeError(err); ok {
			state = string(he.State)
		} else if wire.IsNoHandshakeBytesError(err) {
			state = "premature_close"
		}
		handshakeinstrument.HandshakeFailure("outgoing", state)
		handshakeinstrument.HandshakeDuration("outgoing", "failure", handshakeElapsed)
		c.log.Errorf("Handshake failed: %v", err)
		if c.client.cfg.Callbacks.OnConnFn != nil {
			c.client.cfg.Callbacks.OnConnFn(&ConnectError{Err: err})
		}
		return
	}
	handshakeElapsed := time.Since(handshakeStart)
	handshakeinstrument.HandshakeDuration("outgoing", "success", handshakeElapsed)
	c.log.Debugf("Handshake completed in %v", handshakeElapsed)
	c.client.pki.setClockSkew(int64(w.ClockSkew().Seconds()))

	c.onWireConn(conn, w)
}

// checkSequence validates that the received command sequence matches the expected value.
func checkSequence(expected, actual uint32) error {
	if expected != actual {
		return newProtocolError("invalid/unexpected sequence: %v (Expecting: %v)", actual, expected)
	}
	return nil
}

func (c *connection) onWireConn(conn net.Conn, w *wire.Session) {
	c.onConnStatusChange(nil)

	var wireErr error

	dechunker := cpki.NewDechunker()

	closeConnCh := make(chan error, 1)
	forceCloseConn := func(err error) {
		// We only care about the first error from a callback.
		select {
		case closeConnCh <- err:
		default:
		}
	}
	cmdCloseCh := make(chan interface{})
	defer func() {
		if wireErr == nil {
			// Set a default error if wireErr is nil during shutdown
			wireErr = ErrShutdown
		}
		c.onConnStatusChange(wireErr)
	}()

	// Start the peer reader.
	cmdCh := make(chan interface{})
	c.Go(func() {
		defer close(cmdCh)
		for {
			rawCmd, err := w.RecvCommand(context.Background())
			if err != nil {
				c.log.Debugf("Failed to receive command: %v", err)
				//14:49:09.849 DEBU client/conn: Failed to receive command:
				//read tcp 127.0.0.1:34688->127.0.0.1:30004: use of closed network connection
				select {
				case <-c.HaltCh():
				case cmdCh <- err:
				}
				return
			}
			// The Session re-arms its read idle deadline (ReadTimeout) on every
			// RecvCommand, so a peer that goes silent tears the link down.
			atomic.StoreInt64(&c.retryDelay, int64(2*time.Second))
			select {
			case <-c.HaltCh():
				return
			case cmdCh <- rawCmd:
			case <-cmdCloseCh:
				return
			}
		}
	})

	var consensusCtx *getConsensusCtx
	defer func() {
		if consensusCtx != nil {
			select {
			case <-c.HaltCh():
			case consensusCtx.replyCh <- ErrNotConnected:
			}
		}
	}()

	for {
		var rawCmd commands.Command
		select {
		case ctx := <-c.getConsensusCh:
			if consensusCtx != nil {
				ctx.doneFn(fmt.Errorf("outstanding GetConsensus already exists: %v", consensusCtx.epoch))
			} else {
				consensusCtx = ctx
				cmd := &commands.GetConsensus2{
					Cmds:  w.GetCommands(),
					Epoch: ctx.epoch,
				}
				wireErr = w.SendCommand(context.Background(), cmd)
				ctx.doneFn(wireErr)
				if wireErr != nil {
					c.log.Debugf("Failed to send GetConsensus: %v", wireErr)
					return
				}
			}
			continue
		case ctx := <-c.sendCh:
			cmd := &commands.SendPacket{
				SphinxPacket: ctx.pkt,
				Cmds:         w.GetCommands(),
			}
			wireErr = w.SendCommand(context.Background(), cmd)
			ctx.doneFn(wireErr)
			if wireErr != nil {
				c.log.Debugf("Failed to send SendPacket: %v", wireErr)
				return
			}
			continue
		case tmp, ok := <-cmdCh:
			if !ok {
				wireErr = newProtocolError("command receive worker terminated")
				return
			}
			switch cmdOrErr := tmp.(type) {
			case commands.Command:
				rawCmd = cmdOrErr
			case error:
				wireErr = cmdOrErr
				return
			}
		case <-c.HaltCh():
			wireErr = ErrShutdown
			return
		case wireErr = <-closeConnCh:
			c.log.Debugf("Closing connection due to callback error: %v", wireErr)
			return
		}

		creds, err := w.PeerCredentials()
		if err != nil {
			// do not continue processing this command
			continue
		}
		// Update the cached descriptor, and re-validate the connection.
		if !c.IsPeerValid(creds) {
			c.log.Warningf("No longer have a descriptor for current peer.")
			wireErr = newProtocolError("current consensus no longer lists the Gateway")
			return
		}

		// Handle the response.
		switch cmd := rawCmd.(type) {
		case *commands.NoOp:
			// Gateway's wire-level heartbeat under push delivery;
			// the peer reader has already rearmed the read
			// deadline, so nothing more to do.
			c.log.Debugf("Received NoOp.")
		case *commands.Disconnect:
			c.log.Debugf("Received Disconnect.")
			wireErr = newProtocolError("peer send Disconnect")
			return
		case *commands.Message:
			c.log.Debugf("Received pushed Message: %v", cmd.Sequence)
			seqCopy := cmd.Sequence
			payload := cmd.Payload
			id := cmd.SURBID
			onACK := c.client.cfg.Callbacks.OnACKFn
			if onACK == nil {
				panic("client.cfg.Callbacks.OnACKFn must not be nil")
			}
			c.Go(func() {
				select {
				case <-c.HaltCh():
					return
				default:
				}
				if err := onACK(&id, payload); err != nil {
					c.log.Debugf("Caller failed to handle Message: %v", err)
					forceCloseConn(err)
					return
				}
				ack := &commands.MessageDelivered{
					Sequence: seqCopy,
					Cmds:     w.GetCommands(),
				}
				if err := w.SendCommand(context.Background(), ack); err != nil {
					c.log.Debugf("Failed to send MessageDelivered for Message seq %d: %v", seqCopy, err)
					forceCloseConn(err)
				}
			})
		case *commands.Consensus:
			c.log.Errorf("Received legacy Consensus from gateway when Consensus2 is expected; closing connection.")
			wireErr = newProtocolError("peer sent legacy Consensus instead of Consensus2")
			return
		case *commands.Consensus2:
			if consensusCtx != nil {
				// Check for error responses from the gateway.
				if cmd.ErrorCode != commands.ConsensusOk {
					c.log.Debugf("Received Consensus2 error code: %v for epoch %v", cmd.ErrorCode, consensusCtx.epoch)
					consensusCtx.replyCh <- cmd
					consensusCtx = nil
					dechunker = cpki.NewDechunker()
				} else {
					if dechunker.ChunkNum == 0 {
						dechunker.ChunkNum = int(cmd.ChunkNum)
						dechunker.ChunkTotal = int(cmd.ChunkTotal)
					}
					err = dechunker.Consume(cmd.Payload, int(cmd.ChunkNum), int(cmd.ChunkTotal))
					if err != nil {
						// A chunk-stream error (e.g. EOF when the
						// connection closes mid-fetch, or a chunk
						// numbering inconsistency) must not bring
						// the daemon down. Close the connection and
						// let the supervisor reconnect.
						c.log.Errorf("Consensus2 dechunker error: %v; closing connection.", err)
						wireErr = newProtocolError("consensus dechunker error: %v", err)
						return
					}
					if int(cmd.ChunkNum) == (dechunker.ChunkTotal - 1) {
						if len(dechunker.Output) == 0 {
							// Handle empty dechunker output gracefully during shutdown
							c.log.Debugf("Dechunker output is empty, likely due to shutdown")
							wireErr = newProtocolError("empty consensus response during shutdown")
							return
						}

						// last chunk
						cmd.Payload = make([]byte, len(dechunker.Output))
						copy(cmd.Payload, dechunker.Output)
						consensusCtx.replyCh <- cmd
						consensusCtx = nil
						dechunker = cpki.NewDechunker()
					}
				}
			} else {
				// Spurious Consensus replies are a protocol violation.
				c.log.Errorf("Received spurious Consensus2.")
				wireErr = newProtocolError("received spurious Consensus")
				return
			}
		default:
			c.log.Errorf("Received unexpected command: %T", cmd)
			wireErr = newProtocolError("received unknown command: %T", cmd)
			return
		}
	}
}

func (c *connection) IsPeerValid(creds *wire.PeerCredentials) bool {
	credsKey, err := creds.PublicKey.MarshalBinary()
	if err != nil {
		panic(err)
	}
	if !hmac.Equal(c.descriptor.LinkKey, credsKey) {
		scheme := schemes.ByName(c.client.cfg.WireKEMScheme)
		expectedLinkPubKey, err := scheme.UnmarshalBinaryPublicKey(c.descriptor.LinkKey)
		if err != nil {
			panic(err)
		}
		gotLinkPubKey, err := scheme.UnmarshalBinaryPublicKey(credsKey)
		if err != nil {
			panic(err)
		}
		expected := pem.ToPublicPEMString(expectedLinkPubKey)
		got := pem.ToPublicPEMString(gotLinkPubKey)

		c.log.Warningf("client/connection: IsPeerValid(): Link key mismatch for peer '%s'", c.descriptor.Name)
		c.log.Warningf("client/connection: IsPeerValid(): Expected link key: %s", strings.TrimSpace(expected))
		c.log.Warningf("client/connection: IsPeerValid(): Received link key: %s", strings.TrimSpace(got))
		c.log.Warningf("client/connection: IsPeerValid(): Remote Peer Credentials: name=%s, identity_hash=%x",
			c.descriptor.Name, creds.AdditionalData)
		return false
	}

	identityHash := hash.Sum256(c.descriptor.IdentityKey)
	if !hmac.Equal(identityHash[:], creds.AdditionalData) {
		c.log.Warningf("client/connection: IsPeerValid(): Identity hash mismatch for peer '%s'", c.descriptor.Name)
		c.log.Warningf("client/connection: IsPeerValid(): Expected identity hash: %x", identityHash[:])
		c.log.Warningf("client/connection: IsPeerValid(): Received identity hash: %x", creds.AdditionalData)
		c.log.Warningf("client/connection: IsPeerValid(): Expected identity key (raw): %x", c.descriptor.IdentityKey)
		c.log.Warningf("client/connection: IsPeerValid(): Remote Peer Credentials: name=%s, link_key=%s",
			c.descriptor.Name, strings.TrimSpace(pem.ToPublicPEMString(creds.PublicKey)))
		return false
	}
	return true
}

func (c *connection) onConnStatusChange(err error) {
	if c.isShutdown.Load() {
		return
	}

	if err == nil {
		c.isConnected.Store(true)
		instrument.GatewayConnected(true)
		c.log.Noticef("Connected to gateway %s.", c.gatewayLabel())
	} else {
		c.log.Infof("Lost connection to gateway %s: %s", c.gatewayLabel(), err.Error())
		c.isConnected.Store(false)
		instrument.GatewayConnected(false)
		// Force drain the channels used to poke the loop.
		select {
		case ctx := <-c.sendCh:
			ctx.doneFn(ErrNotConnected)
		default:
		}
		select {
		case ctx := <-c.getConsensusCh:
			ctx.doneFn(ErrNotConnected)
		default:
		}
	}

	if c.client.cfg.Callbacks.OnConnFn != nil {
		c.client.cfg.Callbacks.OnConnFn(err)
	}
}

// sendPacket blocks until the packet is sent
// on the wire.
func (c *connection) sendPacket(pkt []byte) error {
	if !c.isConnected.Load() {
		return ErrNotConnected
	}
	if c.isShutdown.Load() {
		return ErrShutdown
	}

	errCh := make(chan error)
	select {
	case c.sendCh <- &connSendCtx{
		pkt: pkt,
		doneFn: func(err error) {
			errCh <- err
		},
	}:
	case <-c.HaltCh():
		return ErrShutdown
	}

	select {
	case err := <-errCh:
		return err
	case <-c.HaltCh():
		return ErrShutdown
	}
}

func (c *connection) GetConsensus(ctx context.Context, epoch uint64) (*commands.Consensus2, error) {
	if !c.isConnected.Load() {
		return nil, ErrNotConnected
	}

	errCh := make(chan error)
	replyCh := make(chan interface{})

	select {
	case c.getConsensusCh <- &getConsensusCtx{
		replyCh: replyCh,
		epoch:   epoch,
		doneFn: func(err error) {
			errCh <- err
		},
	}:
	case <-ctx.Done():
		// Canceled mid-fetch.
		return nil, errGetConsensusCanceled
	case <-c.HaltCh():
		return nil, ErrShutdown
	}

	// Ensure the dispatch succeeded.
	select {
	case <-c.HaltCh():
		return nil, ErrShutdown
	case err := <-errCh:
		if err != nil {
			c.log.Debugf("Failed to dispatch GetConsensus: %v", err)
			return nil, err
		}
	case <-ctx.Done():
		// Canceled mid-fetch.
		return nil, errGetConsensusCanceled
	}

	// Wait for the dispatch to complete.
	select {
	case <-c.HaltCh():
		return nil, ErrShutdown
	case rawResp := <-replyCh:
		switch resp := rawResp.(type) {
		case error:
			return nil, resp
		case *commands.Consensus2:
			return resp, nil
		default:
			panic("BUG: Worker returned invalid Consensus response")
		}
	case <-ctx.Done():
		// Canceled mid-fetch.
		return nil, errGetConsensusCanceled
	}

	// NOTREACHED
}

func (c *connection) Shutdown() {
	c.isShutdown.Store(true)

	c.Halt()
	close(c.sendCh)
}

func (c *connection) start() {
	c.Go(c.connectWorker)
}

func newConnection(c *Client) *connection {
	k := new(connection)
	k.client = c
	k.log = c.logbackend.GetLogger("client/conn")
	k.sendCh = make(chan *connSendCtx)
	k.getConsensusCh = make(chan *getConsensusCtx, 1)
	return k
}

func addressesFromURLs(addrs []string) map[string][]string {
	addresses := make(map[string][]string)
	for _, addr := range addrs {
		u, err := url.Parse(addr)
		if err != nil {
			continue
		}
		switch u.Scheme {
		case cpki.TransportTCP, cpki.TransportTCPv4, cpki.TransportTCPv6, cpki.TransportQUIC, cpki.TransportOnion:
			if _, ok := addresses[u.Scheme]; !ok {
				addresses[u.Scheme] = make([]string, 0)
			}
			addresses[u.Scheme] = append(addresses[u.Scheme], u.String())
		default:
			continue
		}
	}
	return addresses
}

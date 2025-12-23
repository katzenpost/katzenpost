// SPDX-FileCopyrightText: Copyright (C) 2017  Yawning Angel.
// SPDX-License-Identifier: AGPL-3.0-only

package client2

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

	cpki "github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/wire"
	"github.com/katzenpost/katzenpost/core/wire/commands"
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

	fetchCh        chan interface{}
	sendCh         chan *connSendCtx
	getConsensusCh chan *getConsensusCtx

	retryDelay int64 // used as atomic time.Duration

	isConnectedLock sync.RWMutex
	isConnected     bool

	gatewayLock sync.RWMutex
	gateway     *[32]byte
	queueID     []byte

	isShutdownLock sync.RWMutex
	isShutdown     bool
}

// getGateway safely returns the current gateway hash
func (c *connection) getGateway() *[32]byte {
	c.gatewayLock.RLock()
	defer c.gatewayLock.RUnlock()
	return c.gateway
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

// ForceFetch attempts to force an otherwise idle client to attempt to fetch
// the contents of the user's spool.  This call has no effect if a connection
// is not established or if the connection is already in the middle of a
// fetch cycle, and should be considered a best effort operation.
func (c *Client) ForceFetch() {
	select {
	case c.conn.fetchCh <- true:
	case <-c.HaltCh():
		// Client is shutting down, don't send
	default:
	}
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
	ok := false
	defer func() {
		if !ok {
			c.pkiEpoch = 0
			c.descriptor = nil
		}
	}()

	_, doc := c.client.CurrentDocument()
	if doc == nil && c.client.cfg.CachedDocument == nil {
		c.log.Debugf("No PKI document for current epoch or cached PKI document provide.")
		n := len(c.client.cfg.PinnedGateways.Gateways)
		if n == 0 {
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
				c.isShutdownLock.RLock()
				isShutdown := c.isShutdown
				c.isShutdownLock.RUnlock()
				if !isShutdown {
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

	// Bind the session to the conn, handshake, authenticate.
	conn.SetDeadline(time.Now().Add(handshakeTimeout))
	handshakeStart := time.Now()
	if err = w.Initialize(conn); err != nil {
		c.log.Errorf("Handshake failed: %v", err)
		if c.client.cfg.Callbacks.OnConnFn != nil {
			c.client.cfg.Callbacks.OnConnFn(&ConnectError{Err: err})
		}
		return
	}
	c.log.Debugf("Handshake completed in %v", time.Since(handshakeStart))
	conn.SetDeadline(time.Time{}) // client can take however long it wants
	//if err = conn.SetDeadline(time.Now().Add(90 * time.Second)); err != nil {
	//   panic(err)
	//}
	c.client.pki.setClockSkew(int64(w.ClockSkew().Seconds()))

	c.onWireConn(w)
}

func (c *connection) onWireConn(w *wire.Session) {
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
			rawCmd, err := w.RecvCommand()
			if err != nil {
				c.log.Debugf("Failed to receive command: %v", err)
				//14:49:09.849 DEBU client2/conn: Failed to receive command:
				//read tcp 127.0.0.1:34688->127.0.0.1:30004: use of closed network connection
				select {
				case <-c.HaltCh():
				case cmdCh <- err:
				}
				return
			}
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

	dispatchOnEmpty := func() error {
		if c.client.cfg.Callbacks.OnEmptyFn != nil {
			c.Go(func() {
				select {
				case <-c.HaltCh():
					return
				default:
					if err := c.client.cfg.Callbacks.OnEmptyFn(); err != nil {
						c.log.Debugf("Caller failed to handle MessageEmpty: %v", err)
						forceCloseConn(err)
					}
				}
			})
		}
		return nil
	}

	var consensusCtx *getConsensusCtx
	defer func() {
		if consensusCtx != nil {
			select {
			case <-c.HaltCh():
			case consensusCtx.replyCh <- ErrNotConnected:
			}
		}
	}()

	//var fetchDelay time.Duration
	fetchDelay := time.Second * 3
	var selectAt time.Time
	adjFetchDelay := func() {
		sendAt := time.Now()
		if deltaT := sendAt.Sub(selectAt); deltaT < fetchDelay {
			fetchDelay = fetchDelay - deltaT
		} else {
			fetchDelay = 0 // fetch immediately
		}
	}
	var seq uint32
	checkSeq := func(cmdSeq uint32) error {
		if seq != cmdSeq {
			return newProtocolError("invalid/unexpected sequence: %v (Expecting: %v)", cmdSeq, seq)
		}
		return nil
	}
	nrReqs, nrResps := 0, 0
	for {
		var rawCmd commands.Command
		var doFetch bool
		selectAt = time.Now()
		select {
		case <-time.After(fetchDelay):
			doFetch = true
		case <-c.fetchCh:
			doFetch = true
		case ctx := <-c.getConsensusCh:
			if consensusCtx != nil {
				ctx.doneFn(fmt.Errorf("outstanding GetConsensus already exists: %v", consensusCtx.epoch))
			} else {
				consensusCtx = ctx
				cmd := &commands.GetConsensus2{
					Cmds:  w.GetCommands(),
					Epoch: ctx.epoch,
				}
				wireErr = w.SendCommand(cmd)
				ctx.doneFn(wireErr)
				if wireErr != nil {
					c.log.Debugf("Failed to send GetConsensus: %v", wireErr)
					return
				}
			}

			adjFetchDelay()
			continue
		case ctx := <-c.sendCh:
			cmd := &commands.SendPacket{
				SphinxPacket: ctx.pkt,
				Cmds:         w.GetCommands(),
			}
			wireErr = w.SendCommand(cmd)
			ctx.doneFn(wireErr)
			if wireErr != nil {
				c.log.Debugf("Failed to send SendPacket: %v", wireErr)
				return
			}

			adjFetchDelay()
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

		// Send a fetch if there is not one outstanding.
		if doFetch {
			if nrReqs == nrResps {
				cmd := &commands.RetrieveMessage{
					Sequence: seq,
					Cmds:     w.GetCommands(),
				}
				if wireErr = w.SendCommand(cmd); wireErr != nil {
					c.log.Debugf("Failed to send RetrieveMessage: %v", wireErr)
					return
				}
				nrReqs++
			}
			fetchDelay = c.client.GetPollInterval()
			adjFetchDelay()
			continue
		}

		creds, err := w.PeerCredentials()
		if err != nil {
			// do not continue processing this command
			adjFetchDelay()
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
			c.log.Debugf("Received NoOp.")
		case *commands.Disconnect:
			c.log.Debugf("Received Disconnect.")
			wireErr = newProtocolError("peer send Disconnect")
			return
		case *commands.MessageEmpty:
			if wireErr = checkSeq(cmd.Sequence); wireErr != nil {
				c.log.Errorf("MessageEmpty sequence unexpected: %v", cmd.Sequence)
				return
			}
			nrResps++
			if wireErr = dispatchOnEmpty(); wireErr != nil {
				return
			}
		case *commands.Message:
			c.log.Debugf("Received Message: %v", cmd.Sequence)
			if wireErr = checkSeq(cmd.Sequence); wireErr != nil {
				c.log.Errorf("Message sequence unexpected: %v", cmd.Sequence)
				return
			}
			nrResps++
			if c.client.cfg.Callbacks.OnMessageFn != nil {
				c.Go(func() {
					select {
					case <-c.HaltCh():
						return
					default:
						if err := c.client.cfg.Callbacks.OnMessageFn(cmd.Payload); err != nil {
							c.log.Debugf("Caller failed to handle Message: %v", err)
							forceCloseConn(err)
						}
					}
				})
			}
			seq++
			if cmd.QueueSizeHint == 0 {
				c.log.Debugf("QueueSizeHint indicates empty queue, calling dispatchOnEmpty.")
				if wireErr = dispatchOnEmpty(); wireErr != nil {
					c.log.Debugf("dispatchOnEmpty returned error: %v", wireErr)
					return
				}
			}
		case *commands.MessageACK:
			if wireErr = checkSeq(cmd.Sequence); wireErr != nil {
				c.log.Errorf("MessageACK sequence unexpected: %v", cmd.Sequence)
				return
			}
			nrResps++
			if c.client.cfg.Callbacks.OnACKFn != nil {
				c.Go(func() {
					select {
					case <-c.HaltCh():
						return
					default:
						if err := c.client.cfg.Callbacks.OnACKFn(&cmd.ID, cmd.Payload); err != nil {
							c.log.Debugf("Caller failed to handle MessageACK: %v", err)
							forceCloseConn(err)
						}
					}
				})
			} else {
				panic("client.cfg.Callbacks.OnACKFn must not be nil")
			}
			seq++
		case *commands.Consensus:
			panic("received Consensus when we are supposed to receive Consensus2")
		case *commands.Consensus2:
			if consensusCtx != nil {
				if dechunker.ChunkNum == 0 {
					dechunker.ChunkNum = int(cmd.ChunkNum)
					dechunker.ChunkTotal = int(cmd.ChunkTotal)
				}
				err = dechunker.Consume(cmd.Payload, int(cmd.ChunkNum), int(cmd.ChunkTotal))
				if err != nil {
					panic(err)
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
		adjFetchDelay()
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

		c.log.Warningf("client2/connection: IsPeerValid(): Link key mismatch for peer '%s'", c.descriptor.Name)
		c.log.Warningf("client2/connection: IsPeerValid(): Expected link key: %s", strings.TrimSpace(expected))
		c.log.Warningf("client2/connection: IsPeerValid(): Received link key: %s", strings.TrimSpace(got))
		c.log.Warningf("client2/connection: IsPeerValid(): Remote Peer Credentials: name=%s, identity_hash=%x",
			c.descriptor.Name, creds.AdditionalData)
		return false
	}

	identityHash := hash.Sum256(c.descriptor.IdentityKey)
	if !hmac.Equal(identityHash[:], creds.AdditionalData) {
		c.log.Warningf("client2/connection: IsPeerValid(): Identity hash mismatch for peer '%s'", c.descriptor.Name)
		c.log.Warningf("client2/connection: IsPeerValid(): Expected identity hash: %x", identityHash[:])
		c.log.Warningf("client2/connection: IsPeerValid(): Received identity hash: %x", creds.AdditionalData)
		c.log.Warningf("client2/connection: IsPeerValid(): Expected identity key (raw): %x", c.descriptor.IdentityKey)
		c.log.Warningf("client2/connection: IsPeerValid(): Remote Peer Credentials: name=%s, link_key=%s",
			c.descriptor.Name, strings.TrimSpace(pem.ToPublicPEMString(creds.PublicKey)))
		return false
	}
	return true
}

func (c *connection) onConnStatusChange(err error) {
	c.isShutdownLock.RLock()
	isShutdown := c.isShutdown
	c.isShutdownLock.RUnlock()

	if isShutdown {
		return
	}

	if err == nil {
		c.isConnectedLock.Lock()
		c.isConnected = true
		c.isConnectedLock.Unlock()
	} else {
		c.log.Info("onConnStatusChange %s", err.Error())
		c.isConnectedLock.Lock()
		c.isConnected = false
		c.isConnectedLock.Unlock()
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
		select {
		case <-c.fetchCh:
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
	c.isConnectedLock.RLock()
	if !c.isConnected {
		c.isConnectedLock.RUnlock()
		return ErrNotConnected
	}
	c.isConnectedLock.RUnlock()

	// Check if we're shutting down before sending
	c.isShutdownLock.RLock()
	if c.isShutdown {
		c.isShutdownLock.RUnlock()
		return ErrShutdown
	}
	c.isShutdownLock.RUnlock()

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
	c.isConnectedLock.RLock()
	if !c.isConnected {
		c.isConnectedLock.RUnlock()
		return nil, ErrNotConnected
	}
	c.isConnectedLock.RUnlock()

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
			if len(resp.Payload) == 0 {
				panic("--------------- len(resp.Payload) == 0")
			}

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
	c.isShutdownLock.Lock()
	c.isShutdown = true
	c.isShutdownLock.Unlock()

	c.Halt()
	close(c.fetchCh)
	close(c.sendCh)
}

func (c *connection) start() {
	c.Go(c.connectWorker)
}

func newConnection(c *Client) *connection {
	k := new(connection)
	k.client = c
	k.log = c.logbackend.GetLogger("client2/conn")
	k.fetchCh = make(chan interface{}, 1)
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

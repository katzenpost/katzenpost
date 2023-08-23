// connection.go - Client to provider connection.
// Copyright (C) 2017  Yawning Angel.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package client2

import (
	"context"
	"crypto/hmac"
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/charmbracelet/log"

	"github.com/katzenpost/katzenpost/core/crypto/rand"
	"github.com/katzenpost/katzenpost/core/epochtime"
	cpki "github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/wire"
	"github.com/katzenpost/katzenpost/core/wire/commands"
	"github.com/katzenpost/katzenpost/core/worker"
)

var (
	// ErrNotConnected is the error returned when an operation fails due to the
	// client not currently being connected to the Provider.
	ErrNotConnected = errors.New("client/conn: not connected to the Provider")

	// ErrShutdown is the error returned when the connection is closed due to
	// a call to Shutdown().
	ErrShutdown = errors.New("shutdown requested")

	defaultDialer = net.Dialer{
		KeepAlive: keepAliveInterval,
		Timeout:   connectTimeout,
	}

	keepAliveInterval   = 3 * time.Minute
	connectTimeout      = 1 * time.Minute
	pkiFallbackInterval = epochtime.Period / 16
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
	sync.Mutex
	worker.Worker

	client *Client
	log    *log.Logger

	pkiEpoch   uint64
	descriptor *cpki.MixDescriptor

	pkiFetchCh     chan interface{}
	fetchCh        chan interface{}
	sendCh         chan *connSendCtx
	getConsensusCh chan *getConsensusCtx

	retryDelay  int64 // used as atomic time.Duration
	isConnected bool

	provider *[32]byte
	queueID  []byte
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
	default:
	}
}

// ForceFetchPKI attempts to force client's pkiclient to wake and fetch
// consensus documents immediately.
func (c *Client) ForceFetchPKI() {
	c.log.Debug("ForceFetchPKI()")
	select {
	case c.pki.forceUpdateCh <- true:
	default:
	}
}

func (c *connection) onPKIFetch() {
	c.log.Debug("onPKIFetch")
	select {
	case c.pkiFetchCh <- true:
	default:
		// Probably a connection is in progress, the right thing will happen
		// regardless of if the signal gets dropped, though it might require
		// the fallback timer to fire.
	}
}

func (c *connection) getDescriptor() error {
	c.log.Debug("getDescriptor")

	ok := false
	defer func() {
		if !ok {
			c.pkiEpoch = 0
			c.descriptor = nil
		}
	}()

	doc := c.client.CurrentDocument()
	if doc == nil && c.client.cfg.CachedDocument == nil {
		c.log.Debugf("No PKI document for current epoch or cached PKI document provide.")
		n := len(c.client.cfg.PinnedProviders.Providers)
		if n == 0 {
			return errors.New("No PinnedProviders")
		}
		provider := c.client.cfg.PinnedProviders.Providers[rand.NewMath().Intn(n)]
		idHash := provider.IdentityKey.Sum256()
		c.provider = &idHash
		c.descriptor = &cpki.MixDescriptor{
			Name:        provider.Name,
			IdentityKey: provider.IdentityKey,
			LinkKey:     provider.LinkKey,
			Addresses:   provider.Addresses,
			Provider:    true,
		}
		ok = true
		return nil
	} else {
		doc = c.client.cfg.CachedDocument
	}
	n := len(doc.Providers)
	if n == 0 {
		return errors.New("invalid PKI doc, zero Providers")
	}

	provider := doc.Providers[rand.NewMath().Intn(n)]
	idHash := provider.IdentityKey.Sum256()
	c.provider = &idHash
	desc, err := doc.GetProvider(provider.Name)
	if err != nil {
		c.log.Debugf("Failed to find descriptor for Provider: %v", err)
		return newPKIError("failed to find descriptor for Provider: %v", err)
	}
	if !provider.IdentityKey.Equal(desc.IdentityKey) {
		c.log.Errorf("Provider identity key does not match pinned key: %v", desc.IdentityKey)
		return newPKIError("identity key for Provider does not match pinned key: %v", desc.IdentityKey)
	}
	if desc != c.descriptor {
		c.log.Debugf("Descriptor for epoch %v: %+v", doc.Epoch, desc)
	}

	c.descriptor = desc
	c.pkiEpoch = doc.Epoch
	ok = true

	return nil
}

func (c *connection) connectWorker() {
	c.log.Debug("connectWorker begin")

	defer c.log.Debugf("Terminating connect worker.")

	dialCtx, cancelFn := context.WithCancel(context.Background())
	go func() {
		select {
		case <-c.HaltCh():
			cancelFn()
		case <-dialCtx.Done():
		}
	}()

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
	c.log.Debug("doConnect begin")
	const (
		retryIncrement = 15 * time.Second
		maxRetryDelay  = 2 * time.Minute
	)

	dialFn := c.client.cfg.Callbacks.DialContextFn
	if dialFn == nil {
		dialFn = defaultDialer.DialContext
	}

	var connErr error
	defer func() {
		if connErr == nil {
			panic("BUG: connErr is nil on connection teardown.")
		}

		if c.client.cfg.Callbacks != nil {
			if c.client.cfg.Callbacks.OnConnFn != nil {
				c.client.cfg.Callbacks.OnConnFn(connErr)
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
			c.log.Warnf("Aborting connect loop, no suitable addresses found.")
			c.descriptor = nil // Give up till the next PKI fetch.
			connErr = newConnectError("no suitable addreses found")
			return
		}

		c.log.Debug("doConnect, before for loop")

		for _, addrPort := range dstAddrs {
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

			c.log.Debugf("Dialing: %v", addrPort)
			conn, err := dialFn(dialCtx, "tcp", addrPort)
			select {
			case <-c.HaltCh():
				if conn != nil {
					conn.Close()
				}
				connErr = ErrShutdown
				return
			default:
				if err != nil {
					c.log.Warnf("Failed to connect to %v: %v", addrPort, err)
					if c.client.cfg.Callbacks.OnConnFn != nil {
						c.client.cfg.Callbacks.OnConnFn(&ConnectError{Err: err})
					}
					continue
				}
			}
			c.log.Debugf("TCP connection established.")

			// Do something with the connection.
			c.onTCPConn(conn)

			// Re-iterate through the address/ports on a sucessful connect.
			c.log.Debugf("Connection terminated, will reconnect.")

			// Emit a ConnectError when disconnected.
			c.onConnStatusChange(ErrNotConnected)
			break
		}
	}
}

func (c *connection) onTCPConn(conn net.Conn) {
	c.log.Debug("onTCPConn begin")
	const handshakeTimeout = 1 * time.Minute
	var err error

	defer func() {
		c.log.Debugf("TCP connection closed.")
		conn.Close()
	}()

	c.log.Debug("onTCPConn: GenerateKeypair")
	linkKey, _ := wire.DefaultScheme.GenerateKeypair(rand.Reader)

	// Allocate the session struct.
	userId := make([]byte, 16)
	_, err = rand.Reader.Read(userId)
	if err != nil {
		panic(err)
	}
	c.queueID = []byte(fmt.Sprintf("%x", userId))
	cfg := &wire.SessionConfig{
		Geometry:          c.client.cfg.SphinxGeometry,
		Authenticator:     c,
		AdditionalData:    c.queueID,
		AuthenticationKey: linkKey,
		RandomReader:      rand.Reader,
	}
	c.log.Debug("onTCPConn: NewSession")
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
	c.log.Debug("onTCPConn: before handshake")
	conn.SetDeadline(time.Now().Add(handshakeTimeout))
	if err = w.Initialize(conn); err != nil {
		c.log.Errorf("Handshake failed: %v", err)
		if c.client.cfg.Callbacks.OnConnFn != nil {
			c.client.cfg.Callbacks.OnConnFn(&ConnectError{Err: err})
		}
		return
	}
	c.log.Debugf("onTCPConn: Handshake completed.")
	conn.SetDeadline(time.Time{})
	c.client.pki.setClockSkew(int64(w.ClockSkew().Seconds()))

	c.log.Debug("onTCPConn end")
	c.onWireConn(w)
}

func (c *connection) onWireConn(w *wire.Session) {
	c.log.Debug("onWireConn")
	c.onConnStatusChange(nil)

	var wireErr error

	var cbWg sync.WaitGroup
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
			panic("BUG: wireErr is nil on connection teardown.")
		}
		c.onConnStatusChange(wireErr)
		close(cmdCloseCh)
		cbWg.Wait()
	}()

	// Start the peer reader.
	cmdCh := make(chan interface{})
	go func() {
		defer close(cmdCh)
		for {
			rawCmd, err := w.RecvCommand()
			if err != nil {
				c.log.Debugf("Failed to receive command: %v", err)
				select {
				case <-c.HaltCh():
				case cmdCh <- err:
				}
				return
			}
			atomic.StoreInt64(&c.retryDelay, 0)
			select {
			case <-c.HaltCh():
				return
			case cmdCh <- rawCmd:
			case <-cmdCloseCh:
				return
			}
		}
	}()

	dispatchOnEmpty := func() error {
		if c.client.cfg.Callbacks.OnEmptyFn != nil {
			cbWg.Add(1)
			go func() {
				defer cbWg.Done()
				if err := c.client.cfg.Callbacks.OnEmptyFn(); err != nil {
					c.log.Debugf("Caller failed to handle MessageEmpty: %v", err)
					forceCloseConn(err)
				}
			}()
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
			fetchDelay = time.Second * 3
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
			c.log.Debugf("Dequeued GetConsesus for send.")
			if consensusCtx != nil {
				ctx.doneFn(fmt.Errorf("outstanding GetConsensus already exists: %v", consensusCtx.epoch))
			} else {
				consensusCtx = ctx
				cmd := &commands.GetConsensus{
					Epoch: ctx.epoch,
				}
				wireErr = w.SendCommand(cmd)
				ctx.doneFn(wireErr)
				if wireErr != nil {
					c.log.Debugf("Failed to send GetConsensus: %v", wireErr)
					return
				}
				c.log.Debugf("Sent GetConsensus.")
			}

			adjFetchDelay()
			continue
		case ctx := <-c.sendCh:
			c.log.Debugf("Dequeued packet for send.")
			cmd := &commands.SendPacket{
				SphinxPacket: ctx.pkt,
			}
			wireErr = w.SendCommand(cmd)
			ctx.doneFn(wireErr)
			if wireErr != nil {
				c.log.Debugf("Failed to send SendPacket: %v", wireErr)
				return
			}
			c.log.Debugf("Sent SendPacket.")

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
				}
				if wireErr = w.SendCommand(cmd); wireErr != nil {
					c.log.Debugf("Failed to send RetrieveMessage: %v", wireErr)
					return
				}
				c.log.Debugf("Sent RetrieveMessage: %d", seq)
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
			c.log.Warnf("No longer have a descriptor for current peer.")
			wireErr = newProtocolError("current consensus no longer lists the Provider")
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
			c.log.Debugf("Received MessageEmpty: %v", cmd.Sequence)
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
				cbWg.Add(1)
				go func() {
					defer cbWg.Done()
					if err := c.client.cfg.Callbacks.OnMessageFn(cmd.Payload); err != nil {
						c.log.Debugf("Caller failed to handle Message: %v", err)
						forceCloseConn(err)
					}
				}()
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
			c.log.Debugf("Received MessageACK: %v", cmd.Sequence)
			if wireErr = checkSeq(cmd.Sequence); wireErr != nil {
				c.log.Errorf("MessageACK sequence unexpected: %v", cmd.Sequence)
				return
			}
			nrResps++
			if c.client.cfg.Callbacks.OnACKFn != nil {
				cbWg.Add(1)
				go func() {
					defer cbWg.Done()
					if err := c.client.cfg.Callbacks.OnACKFn(&cmd.ID, cmd.Payload); err != nil {
						c.log.Debugf("Caller failed to handle MessageACK: %v", err)
						forceCloseConn(err)
					}
				}()
			} else {
				panic("client.cfg.Callbacks.OnACKFn must not be nil")
			}
			seq++
		case *commands.Consensus:
			if consensusCtx != nil {
				c.log.Debugf("Received Consensus: ErrorCode: %v, Payload %v bytes", cmd.ErrorCode, len(cmd.Payload))
				consensusCtx.replyCh <- cmd
				consensusCtx = nil
			} else {
				// Spurious Consensus replies are a protocol violation.
				c.log.Errorf("Received spurious Consensus.")
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
	if !c.descriptor.LinkKey.Equal(creds.PublicKey) {
		return false
	}

	identityHash := c.descriptor.IdentityKey.Sum256()
	if !hmac.Equal(identityHash[:], creds.AdditionalData) {
		return false
	}
	return true
}

func (c *connection) onConnStatusChange(err error) {
	c.log.Info("onConnStatusChange")
	c.Lock()
	if err == nil {
		c.isConnected = true
	} else {
		c.isConnected = false
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
	c.Unlock()

	if c.client.cfg.Callbacks.OnConnFn != nil {
		c.client.cfg.Callbacks.OnConnFn(err)
	}
}

func (c *connection) sendPacket(pkt []byte) error {
	c.log.Debug("sendPacket")
	c.Lock()
	if !c.isConnected {
		c.Unlock()
		return ErrNotConnected
	}
	c.Unlock()

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
	c.log.Debugf("Enqueued packet for send.")

	select {
	case err := <-errCh:
		return err
	case <-c.HaltCh():
		return ErrShutdown
	}
}

func (c *connection) getConsensus(ctx context.Context, epoch uint64) (*commands.Consensus, error) {
	c.log.Debug("getConsensus")
	c.Lock()
	if !c.isConnected {
		c.Unlock()
		return nil, ErrNotConnected
	}
	c.Unlock()

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
	case <-c.HaltCh():
		return nil, ErrShutdown
	}
	c.log.Debug("Enqueued GetConsensus command for send.")

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
		case *commands.Consensus:
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

func (c *connection) start() {
	c.log.Debug("start")
	c.Go(c.connectWorker)
}

func newConnection(c *Client) *connection {
	k := new(connection)
	k.client = c
	k.log = log.NewWithOptions(os.Stderr, log.Options{
		Prefix: "client2/conn",
		Level:  log.DebugLevel,
	})

	k.log.Debug("newConnection")

	k.pkiFetchCh = make(chan interface{}, 1)
	k.fetchCh = make(chan interface{}, 1)
	k.sendCh = make(chan *connSendCtx)
	k.getConsensusCh = make(chan *getConsensusCtx, 1)
	return k
}

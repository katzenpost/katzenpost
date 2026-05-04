// SPDX-FileCopyrightText: © 2023 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package client

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/fxamacker/cbor/v2"
	"gopkg.in/op/go-logging.v1"

	"github.com/katzenpost/hpqc/rand"

	"github.com/katzenpost/katzenpost/client/thin"
	sphinxConstants "github.com/katzenpost/katzenpost/core/sphinx/constants"
)

const (
	// perClientRequestBuf is the capacity of each thin client's ingress
	// queue. When full, that client's reader goroutine blocks on its own
	// queue — back-pressure stays isolated instead of spilling into a
	// shared buffer where it would stall other clients.
	perClientRequestBuf = 16

	// perClientResendBuf is the capacity of each thin client's ARQ resend
	// queue. If full, enqueueResend re-arms the retry on arqTimerQueue
	// (see resendQueueFullBackoff) so no retransmit is silently lost.
	perClientResendBuf = 8

	// perClientWriteDeadline bounds how long a socket write can block
	// before the per-conn writer gives up and tears down the conn. Without
	// this, a wedged thin client would cause the unbounded sendQueue to
	// grow indefinitely. 60s is generous for any healthy client while
	// still bounding memory in the pathological case.
	perClientWriteDeadline = 60 * time.Second
)

// errConnClosed is returned by sendResponse when the incoming conn has
// already begun teardown, so the caller knows the response can not be
// delivered rather than silently queueing onto a dead conn.
var errConnClosed = errors.New("incomingConn closed")

// incomingConn type is used along with listener type
type incomingConn struct {
	listener *listener
	log      *logging.Logger

	conn  net.Conn
	appID *[AppIDLength]byte

	clientToken   *[16]byte
	explicitClose bool

	// requestCh is this client's per-connection ingress queue, drained by
	// the listener's round-robin scheduler. Bursts from one client fill
	// that client's own queue and apply back-pressure to its own reader,
	// without contending with other clients' requests.
	requestCh chan *Request

	// resendCh carries ARQ resend SURB IDs targeted at this client. The
	// scheduler picks from resendCh before requestCh within a client's
	// slot so retransmits are not delayed behind fresh user input.
	resendCh chan *[sphinxConstants.SURBIDLength]byte

	// sendQueue is this client's outbound slice queue. sendResponse
	// appends under sendQueueMu (never drops); the per-conn writer
	// goroutine drains a batch under the same mutex and Writes each
	// response without holding it. The queue is unbounded so shared
	// workers (ingressWorker / egressWorker) never lose a response just
	// because one thin client is slow to read — memory growth is
	// bounded instead by the write deadline on each socket Write: a
	// wedged client triggers conn teardown well before the queue grows
	// pathologically.
	sendQueue   []*Response
	sendQueueMu sync.Mutex

	// sendWake is a 1-capacity wake channel; sendResponse signals it
	// after appending so the writer goroutine notices new work.
	sendWake chan struct{}

	// doneCh is closed exactly once when this conn begins teardown, so
	// sendResponse can fail fast rather than queueing onto a dead conn
	// and any goroutine waiting for the writer can unwind.
	doneCh   chan struct{}
	doneOnce sync.Once
}

// closeDone closes doneCh exactly once. Called from the worker's defer
// path and from the writer goroutine if its socket Write fails.
func (c *incomingConn) closeDone() {
	c.doneOnce.Do(func() { close(c.doneCh) })
}

// isDone reports whether the conn has already begun teardown.
func (c *incomingConn) isDone() bool {
	select {
	case <-c.doneCh:
		return true
	default:
		return false
	}
}

func (c *incomingConn) recvRequest() (*Request, error) {
	req := new(thin.Request)
	const prefixLength = 4
	lenPrefix := [prefixLength]byte{}
	count, err := io.ReadFull(c.conn, lenPrefix[:])
	if err != nil {
		return nil, err
	}
	if count != prefixLength {
		return nil, errors.New("failed to read length prefix")
	}
	blobLen := binary.BigEndian.Uint32(lenPrefix[:])
	blob := make([]byte, blobLen)
	if count, err = io.ReadFull(c.conn, blob); err != nil {
		return nil, err
	}
	if uint32(count) != blobLen {
		return nil, errors.New("failed to read blob")
	}
	err = cbor.Unmarshal(blob[:count], &req)
	if err != nil {
		c.log.Infof("error decoding cbor from client: %s\n", err)
		return nil, err
	}
	return FromThinRequest(req, c.appID), nil
}

func (c *incomingConn) sendPKIDoc(doc []byte) error {
	return c.sendResponse(&Response{
		NewPKIDocumentEvent: &thin.NewPKIDocumentEvent{
			Payload: doc,
		},
	})
}

func (c *incomingConn) updateConnectionStatus(status error) {
	c.sendResponse(&Response{
		ConnectionStatusEvent: &thin.ConnectionStatusEvent{
			IsConnected:   status == nil,
			Err:           nil,
			InstanceToken: c.listener.instanceToken,
		},
	})
}

// sendResponse enqueues a response for this thin client. Never drops:
// it appends to the per-conn sendQueue under sendQueueMu and signals
// the writer goroutine via sendWake. The only error returned is
// errConnClosed, meaning the conn has already begun teardown and the
// response cannot be delivered — callers can then treat it as "client
// gone" rather than mistake it for a buffering decision inside the
// daemon.
func (c *incomingConn) sendResponse(r *Response) error {
	c.sendQueueMu.Lock()
	if c.isDone() {
		c.sendQueueMu.Unlock()
		return errConnClosed
	}
	c.sendQueue = append(c.sendQueue, r)
	c.sendQueueMu.Unlock()

	select {
	case c.sendWake <- struct{}{}:
	default:
	}
	return nil
}

// drainSendQueue atomically returns the current batch and empties the
// queue. The returned slice aliases the old backing array; callers
// must not mutate it.
func (c *incomingConn) drainSendQueue() []*Response {
	c.sendQueueMu.Lock()
	batch := c.sendQueue
	c.sendQueue = nil
	c.sendQueueMu.Unlock()
	return batch
}

// writeResponse performs the actual socket write. Called only by the
// per-conn writer goroutine (drained from sendQueue) and by
// broadcastShutdownEvent during shutdown, when the writer goroutine may
// have already exited. A write deadline bounds how long a wedged client
// can pin the writer; on deadline the socket Write returns an error and
// the caller tears down the conn.
func (c *incomingConn) writeResponse(r *Response) error {
	response := IntoThinResponse(r)
	blob, err := cbor.Marshal(response)
	if err != nil {
		c.log.Errorf("writeResponse: cbor.Marshal: %v", err)
		return err
	}

	const blobPrefixLen = 4
	prefix := [blobPrefixLen]byte{}
	binary.BigEndian.PutUint32(prefix[:], uint32(len(blob)))
	total := int64(blobPrefixLen + len(blob))

	// SetWriteDeadline may not be supported by every transport (e.g.
	// net.Pipe in tests); ignore the error and rely on the underlying
	// Write to fail promptly either way.
	_ = c.conn.SetWriteDeadline(time.Now().Add(perClientWriteDeadline))
	// net.Buffers.WriteTo coalesces into a single writev syscall on
	// transports that support it (tcp, unix); otherwise it emits two
	// Writes. Either way we avoid the append+copy of prefix+blob.
	bufs := net.Buffers{prefix[:], blob}
	n, err := bufs.WriteTo(c.conn)
	_ = c.conn.SetWriteDeadline(time.Time{})
	if err != nil {
		c.log.Errorf("writeResponse: Write: %v", err)
		return err
	}
	if n != total {
		c.log.Errorf("writeResponse: Write: truncated write (%d/%d)", n, total)
		return fmt.Errorf("writeResponse error: only wrote %d bytes whereas buffer is size %d", n, total)
	}
	return nil
}

func (c *incomingConn) start() {
	c.listener.Go(c.worker)
}

func (c *incomingConn) worker() {
	defer func() {
		c.closeDone()
		c.log.Debugf("Closing.")
		c.conn.Close()
		c.listener.onClosedConn(c) // Remove from the connection list.
	}()

	// Start reading from the unix socket peer.
	requestCh := make(chan *Request)
	requestCloseCh := make(chan interface{})
	defer close(requestCloseCh)
	c.listener.Go(func() {
		defer close(requestCh)
		for {
			rawCmd, err := c.recvRequest()
			if err != nil {
				c.log.Debugf("Failed to receive command: %v", err)
				return
			}
			select {
			case requestCh <- rawCmd:
			case <-requestCloseCh:
				// c.worker() is returning for some reason, give up on
				// trying to write the command, and just return.
				return
			case <-c.listener.HaltCh():
				return
			}
		}
	})

	// Writer goroutine: drain batches from sendQueue, Write them to
	// the socket. A Write failure (including hitting the write
	// deadline) tears down the conn by closing doneCh, which causes
	// further sendResponse calls to return errConnClosed rather than
	// queueing onto a dead writer.
	c.listener.Go(func() {
		defer c.closeDone()
		for {
			for _, resp := range c.drainSendQueue() {
				if err := c.writeResponse(resp); err != nil {
					c.log.Infof("writer exiting after write error: %s", err.Error())
					return
				}
			}
			select {
			case <-c.listener.HaltCh():
				return
			case <-c.doneCh:
				return
			case <-c.sendWake:
			}
		}
	})

	for {
		var rawReq *Request
		var ok bool

		select {
		case <-c.listener.HaltCh():
			return
		case rawReq, ok = <-requestCh:
			if !ok {
				return
			}
			if rawReq.ThinClose != nil {
				c.explicitClose = true
				c.log.Info("Thin client sent a disconnect request, closing thin client connection.")
				return
			}
			if rawReq.SessionToken != nil {
				c.listener.handleSessionToken(c, rawReq.SessionToken)
				continue
			}
			c.log.Infof("Received Request from peer application.")
			if isLocalRequest(rawReq) && c.listener.localDispatch != nil {
				// Local-only operations (key generation, envelope prep,
				// box-index arithmetic, ARQ cancellation) do no mixnet
				// I/O and so should not consume a Poisson send slot.
				// Running inline on this reader goroutine also
				// guarantees per-client ordering with any subsequent
				// mixnet-bound request from the same thin client.
				c.listener.localDispatch(rawReq)
				continue
			}
			select {
			case c.requestCh <- rawReq:
			case <-c.listener.HaltCh():
				return
			}
		}
	}
	// NOTREACHED
}

func newIncomingConn(l *listener, conn net.Conn) *incomingConn {

	appid := new([AppIDLength]byte)
	_, err := rand.Reader.Read(appid[:])
	if err != nil {
		panic(err)
	}

	c := &incomingConn{
		listener:  l,
		conn:      conn,
		appID:     appid,
		requestCh: make(chan *Request, perClientRequestBuf),
		resendCh:  make(chan *[sphinxConstants.SURBIDLength]byte, perClientResendBuf),
		sendWake:  make(chan struct{}, 1),
		doneCh:    make(chan struct{}),
	}

	c.log = l.logBackend.GetLogger("client/incomingConn")
	c.log.Debugf("New incoming connection. Remote addr: %v assigned App ID: %x", conn.RemoteAddr(), appid[:])

	// Note: Unlike most other things, this does not spawn the worker here,
	// because the worker needs to be spawned after the struct is added to
	// the connection list.

	return c
}

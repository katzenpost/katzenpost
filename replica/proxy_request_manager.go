// SPDX-FileCopyrightText: Copyright (C) 2025 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package replica

import (
	"context"
	"sync"
	"time"

	"gopkg.in/op/go-logging.v1"

	"github.com/katzenpost/hpqc/nike"

	"github.com/katzenpost/katzenpost/core/wire/commands"
	"github.com/katzenpost/katzenpost/replica/instrument"
)

var defaultCleanupInterval = 30 * time.Second

// ProxyRequest represents a pending proxy request
type ProxyRequest struct {
	ResponseCh      chan *commands.ReplicaMessageReply
	MKEMPrivateKey  nike.PrivateKey
	TargetPublicKey nike.PublicKey
	OriginalRequest *commands.ReplicaMessage
	Timestamp       time.Time
	PeerIDHash      [32]byte
	PeerName        string
}

// ProxyRequestManager manages pending proxy requests
type ProxyRequestManager struct {
	sync.RWMutex
	pendingRequests map[[32]byte]*ProxyRequest
	log             *logging.Logger
	requestTimeout  time.Duration

	// Cleanup goroutine management
	ctx       context.Context
	cancel    context.CancelFunc
	cleanupWg sync.WaitGroup
}

// NewProxyRequestManager creates a new proxy request manager
func NewProxyRequestManager(log *logging.Logger, requestTimeout time.Duration) *ProxyRequestManager {
	ctx, cancel := context.WithCancel(context.Background())

	if requestTimeout <= 0 {
		requestTimeout = defaultCleanupInterval
	}

	p := &ProxyRequestManager{
		pendingRequests: make(map[[32]byte]*ProxyRequest),
		log:             log,
		requestTimeout:  requestTimeout,
		ctx:             ctx,
		cancel:          cancel,
	}

	// Start the periodic cleanup goroutine
	p.cleanupWg.Add(1)
	go p.periodicCleanup()

	return p
}

// publishPendingLocked republishes the pending-request gauge. Must be
// called with the lock held after any operation that mutates
// pendingRequests (register, fail, reply, shutdown, or cleanup).
// Reading len() means a single call after a batch of deletions
// is correct.
func (p *ProxyRequestManager) publishPendingLocked() {
	instrument.ProxyPendingRequests(len(p.pendingRequests))
}

// RegisterProxyRequest registers a new proxy request and returns a response channel
func (p *ProxyRequestManager) RegisterProxyRequest(envelopeHash [32]byte, mkemPrivateKey nike.PrivateKey, targetPublicKey nike.PublicKey, originalRequest *commands.ReplicaMessage, peerIDHash [32]byte, peerName string) chan *commands.ReplicaMessageReply {
	p.Lock()
	defer p.Unlock()

	responseCh := make(chan *commands.ReplicaMessageReply, 1)

	p.pendingRequests[envelopeHash] = &ProxyRequest{
		ResponseCh:      responseCh,
		MKEMPrivateKey:  mkemPrivateKey,
		TargetPublicKey: targetPublicKey,
		OriginalRequest: originalRequest,
		Timestamp:       time.Now(),
		PeerIDHash:      peerIDHash,
		PeerName:        peerName,
	}

	p.publishPendingLocked()
	p.log.Debugf("Registered proxy request to %s for envelope hash: %x", peerName, envelopeHash)

	return responseCh
}

// FailPeer fails every pending proxy request targeting the given peer.
// Called when the peer's connection dies so waiters fail over to the
// other shard holder immediately instead of burning the full
// ProxyRequestTimeout against a dead session.
func (p *ProxyRequestManager) FailPeer(peerIDHash [32]byte) {
	p.Lock()
	defer p.Unlock()

	for hash, request := range p.pendingRequests {
		if request.PeerIDHash != peerIDHash {
			continue
		}
		p.log.Warningf("Failing pending proxy request to %s (connection died): envelope hash %x", request.PeerName, hash)
		close(request.ResponseCh)
		delete(p.pendingRequests, hash)
	}
	p.publishPendingLocked()
}

// FailRequest ends one pending proxy request by envelope hash, closing
// its response channel and dropping the registration. reason names the
// circumstance for the log.
//
// Two circumstances reach it. The request could not be handed to the
// peer at all: with no command on the wire there is no reply coming, so
// the waiter would otherwise burn its whole share of the sweep budget
// against nothing and only then fail over to the co-holder. Or the
// waiter has already spent that share and left, in which case the entry
// must go with it rather than linger until the periodic cleanup expires
// it against the whole ProxyRequestTimeout. Sibling of FailPeer, which
// does the same for every request to a peer whose session died.
//
// A request already answered or already failed is gone from the map, so
// calling this after either is a silent no-op.
func (p *ProxyRequestManager) FailRequest(envelopeHash [32]byte, reason string) {
	p.Lock()
	defer p.Unlock()

	request, exists := p.pendingRequests[envelopeHash]
	if !exists {
		return
	}
	p.log.Warningf("Failing pending proxy request to %s (%s): envelope hash %x", request.PeerName, reason, envelopeHash)
	close(request.ResponseCh)
	delete(p.pendingRequests, envelopeHash)
	p.publishPendingLocked()
}

// HandleReply processes an incoming reply and routes it to the waiting request
func (p *ProxyRequestManager) HandleReply(reply *commands.ReplicaMessageReply) bool {
	if reply.EnvelopeHash == nil {
		p.log.Warningf("Received reply with nil envelope hash")
		return false
	}

	// Claim the request under the lock, then do the channel work
	// outside it. Holding the manager lock across a channel operation
	// invites contention between the outgoing connections that call
	// this and every other path that touches pendingRequests.
	p.Lock()
	request, exists := p.pendingRequests[*reply.EnvelopeHash]
	if !exists {
		p.Unlock()
		p.log.Debugf("No pending request found for envelope hash: %x", reply.EnvelopeHash)
		return false
	}
	responseCh := request.ResponseCh
	delete(p.pendingRequests, *reply.EnvelopeHash)
	p.publishPendingLocked()
	p.Unlock()

	p.log.Debugf("PROXY REPLY RECEIVED: Found pending request for envelope hash: %x", reply.EnvelopeHash)

	// This send cannot block, so it needs no shutdown escape. Removing
	// the map entry above made us the channel's exclusive owner, no
	// other path can now find it, the channel has capacity one, and
	// this is the only site in the package that ever sends on it, so
	// the buffer is necessarily empty. A select on ctx.Done() here
	// would be unreachable, and worse than unreachable: taking it
	// would return with the entry already deleted and the channel
	// neither sent to nor closed, orphaning a waiter that Shutdown can
	// no longer reach.
	responseCh <- reply
	close(responseCh)
	p.log.Debugf("PROXY REPLY ROUTED: Successfully routed reply to waiting proxy request for envelope hash: %x", reply.EnvelopeHash)
	return true
}

// periodicCleanup runs a periodic cleanup of expired proxy requests
func (p *ProxyRequestManager) periodicCleanup() {
	defer p.cleanupWg.Done()

	// Clean up every 10 seconds
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-p.ctx.Done():
			p.log.Debug("Proxy request manager cleanup goroutine shutting down")
			return
		case <-ticker.C:
			p.CleanupExpiredRequests(p.requestTimeout)
		}
	}
}

// Shutdown gracefully shuts down the proxy request manager
func (p *ProxyRequestManager) Shutdown() {
	p.log.Debug("Shutting down proxy request manager")

	// Cancel the context to stop the cleanup goroutine
	p.cancel()

	// Wait for the cleanup goroutine to finish
	p.cleanupWg.Wait()

	// Clean up any remaining requests
	p.Lock()
	defer p.Unlock()

	for hash, request := range p.pendingRequests {
		p.log.Debugf("Cleaning up remaining proxy request for envelope hash: %x", hash)
		close(request.ResponseCh)
		delete(p.pendingRequests, hash)
	}
	p.publishPendingLocked()
}

// CleanupExpiredRequests removes requests that have been waiting too long
func (p *ProxyRequestManager) CleanupExpiredRequests(timeout time.Duration) {
	p.Lock()
	defer p.Unlock()

	now := time.Now()
	for hash, request := range p.pendingRequests {
		if now.Sub(request.Timestamp) > timeout {
			p.log.Warningf("Cleaning up expired proxy request for envelope hash: %x", hash)
			close(request.ResponseCh)
			delete(p.pendingRequests, hash)
		}
	}
	p.publishPendingLocked()
}

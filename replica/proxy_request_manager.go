// SPDX-FileCopyrightText: Copyright (C) 2025 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package replica

import (
	"context"
	"sync"
	"time"

	"github.com/katzenpost/hpqc/nike"
	"github.com/katzenpost/katzenpost/core/wire/commands"
	"gopkg.in/op/go-logging.v1"
)

var cleanupInterval = 30 * time.Second

// ProxyRequest represents a pending proxy request
type ProxyRequest struct {
	ResponseCh      chan *commands.ReplicaMessageReply
	MKEMPrivateKey  nike.PrivateKey
	TargetPublicKey nike.PublicKey
	OriginalRequest *commands.ReplicaMessage
	Timestamp       time.Time
}

// ProxyRequestManager manages pending proxy requests
type ProxyRequestManager struct {
	sync.RWMutex
	pendingRequests map[[32]byte]*ProxyRequest
	log             *logging.Logger

	// Cleanup goroutine management
	ctx       context.Context
	cancel    context.CancelFunc
	cleanupWg sync.WaitGroup
}

// NewProxyRequestManager creates a new proxy request manager
func NewProxyRequestManager(log *logging.Logger) *ProxyRequestManager {
	ctx, cancel := context.WithCancel(context.Background())

	p := &ProxyRequestManager{
		pendingRequests: make(map[[32]byte]*ProxyRequest),
		log:             log,
		ctx:             ctx,
		cancel:          cancel,
	}

	// Start the periodic cleanup goroutine
	p.cleanupWg.Add(1)
	go p.periodicCleanup()

	return p
}

// RegisterProxyRequest registers a new proxy request and returns a response channel
func (p *ProxyRequestManager) RegisterProxyRequest(envelopeHash [32]byte, mkemPrivateKey nike.PrivateKey, targetPublicKey nike.PublicKey, originalRequest *commands.ReplicaMessage) chan *commands.ReplicaMessageReply {
	p.Lock()
	defer p.Unlock()

	responseCh := make(chan *commands.ReplicaMessageReply, 1)

	p.pendingRequests[envelopeHash] = &ProxyRequest{
		ResponseCh:      responseCh,
		MKEMPrivateKey:  mkemPrivateKey,
		TargetPublicKey: targetPublicKey,
		OriginalRequest: originalRequest,
		Timestamp:       time.Now(),
	}

	p.log.Debugf("Registered proxy request for envelope hash: %x", envelopeHash)

	return responseCh
}

// HandleReply processes an incoming reply and routes it to the waiting request
func (p *ProxyRequestManager) HandleReply(reply *commands.ReplicaMessageReply) bool {
	if reply.EnvelopeHash == nil {
		p.log.Warningf("Received reply with nil envelope hash")
		return false
	}

	p.Lock()
	defer p.Unlock()

	request, exists := p.pendingRequests[*reply.EnvelopeHash]
	if !exists {
		p.log.Debugf("No pending request found for envelope hash: %x", reply.EnvelopeHash)
		return false
	}

	p.log.Debugf("PROXY REPLY RECEIVED: Found pending request for envelope hash: %x", reply.EnvelopeHash)

	// Send the reply to the waiting channel
	select {
	case request.ResponseCh <- reply:
		p.log.Debugf("PROXY REPLY ROUTED: Successfully routed reply to waiting proxy request for envelope hash: %x", reply.EnvelopeHash)
	case <-p.ctx.Done():
		p.log.Warning("halting...")
		return false
	}

	// Clean up the request
	delete(p.pendingRequests, *reply.EnvelopeHash)
	close(request.ResponseCh)
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
			p.CleanupExpiredRequests(cleanupInterval)
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
}

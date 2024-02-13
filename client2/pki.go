// SPDX-FileCopyrightText: Copyright (C) 2017  Yawning Angel.
// SPDX-License-Identifier: AGPL-3.0-only

package client2

import (
	"context"
	"crypto/hmac"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/charmbracelet/log"

	vServer "github.com/katzenpost/katzenpost/authority/voting/server"
	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/log2"
	cpki "github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/wire/commands"
	"github.com/katzenpost/katzenpost/core/worker"
)

var (
	errGetConsensusCanceled = errors.New("client/pki: consensus fetch canceled")
	errConsensusNotFound    = errors.New("client/pki: consensus not ready yet")
	PublishDeadline         = vServer.PublishConsensusDeadline
	mixServerCacheDelay     = epochtime.Period / 16
	nextFetchTill           = epochtime.Period - (PublishDeadline + mixServerCacheDelay)
	recheckInterval         = epochtime.Period / 16
	// WarpedEpoch is a build time flag that accelerates the recheckInterval
	WarpedEpoch = "false"
)

type ConsensusGetter interface {
	GetConsensus(ctx context.Context, epoch uint64) (*commands.Consensus, error)
}

type pki struct {
	worker.Worker

	c               *Client
	consensusGetter ConsensusGetter

	log *log.Logger

	docs          sync.Map
	failedFetches map[uint64]error

	clockSkewLock sync.RWMutex
	clockSkew     int64

	forceUpdateCh chan interface{}
}

// ClockSkew returns the current best guess difference between the client's
// system clock and the network's global clock, rounded to the nearest second,
// as measured against the provider during the handshake process.  Calls to
// this routine should not be made until the first `ClientConfig.OnConnFn(true)`
// callback.
func (c *Client) ClockSkew() time.Duration {
	c.pki.clockSkewLock.RLock()
	defer c.pki.clockSkewLock.RUnlock()

	return time.Duration(c.pki.clockSkew) * time.Second
}

// CurrentDocument returns the current pki.Document, or nil iff one does not
// exist.  The caller MUST NOT modify the returned object in any way.
func (c *Client) CurrentDocument() *cpki.Document {
	c.WaitForCurrentDocument()
	return c.pki.currentDocument()
}

func (c *Client) WaitForCurrentDocument() {
	if c.pki.currentDocument() != nil {
		return
	}
	epoch, _, _ := epochtime.Now()
	err := c.pki.updateDocument(epoch)
	if err != nil {
		c.log.Errorf("WaitForCurrentDocument failed on updateDocument with err: %s", err.Error())
	}
}

func (p *pki) setClockSkew(skew int64) {
	p.log.Debugf("New clock skew: %v sec", skew)
	p.clockSkewLock.Lock()
	p.clockSkew = skew
	p.clockSkewLock.Unlock()

	// Wake up the worker if able to.
	select {
	case p.forceUpdateCh <- true:
	default:
	}
}

func (p *pki) skewedUnixTime() int64 {
	if !p.c.cfg.Debug.EnableTimeSync {
		return time.Now().Unix()
	}

	p.clockSkewLock.RLock()
	defer p.clockSkewLock.RUnlock()

	return time.Now().Unix() + p.clockSkew
}

func (p *pki) currentDocument() *cpki.Document {
	now, _, _ := epochtime.FromUnix(p.skewedUnixTime())
	if d, _ := p.docs.Load(now); d != nil {
		return d.(*cpki.Document)
	}

	return nil
}

func (p *pki) worker() {
	p.log.Debug("worker")
	defer p.log.Debug("stopping worker")
	timer := time.NewTimer(0)
	defer func() {
		p.log.Debug("Halting PKI worker.")
		timer.Stop()
	}()

	var lastCallbackEpoch uint64
	for {
		timerFired := false
		select {
		case <-p.HaltCh():
			p.log.Debugf("Terminating gracefully.")
			return
		case <-p.forceUpdateCh:
		case <-timer.C:
			timerFired = true
		}
		if !timerFired && !timer.Stop() {
			select {
			case <-timer.C:
			case <-p.HaltCh():
				p.log.Debugf("Terminating gracefully.")
				return
			}
		}

		// Use the skewed time to determine which documents to fetch.
		epochs := make([]uint64, 0, 2)
		now, _, till := epochtime.FromUnix(p.skewedUnixTime())
		epochs = append(epochs, now)
		if till < nextFetchTill {
			epochs = append(epochs, now+1)
		}
		// Fetch the documents that we are missing.
		didUpdate := false
		for _, epoch := range epochs {
			if _, ok := p.docs.Load(epoch); ok {
				continue
			}

			// Certain errors in fetching documents are treated as hard
			// failures that suppress further attempts to fetch the document
			// for the epoch.
			if err, ok := p.failedFetches[epoch]; ok {
				p.log.Debugf("Skipping fetch for epoch %v: %v", epoch, err)
				continue
			}

			err := p.updateDocument(epoch)
			if err != nil {
				p.log.Warnf("Failed to fetch PKI for epoch %v: %v", epoch, err)
				switch err {
				case cpki.ErrNoDocument:
					p.failedFetches[epoch] = err
				case errGetConsensusCanceled:
					return
				default:
				}
				continue
			}
			didUpdate = true
		}
		p.pruneFailures(now)
		if didUpdate {
			// Prune documents.
			p.pruneDocuments(now)

		}
		if now != lastCallbackEpoch && p.c.cfg.Callbacks.OnDocumentFn != nil {
			if d, ok := p.docs.Load(now); ok {
				lastCallbackEpoch = now
				p.c.cfg.Callbacks.OnDocumentFn(d.(*cpki.Document))
			}
		}
		timer.Reset(recheckInterval)
	}

	// NOTREACHED
}

func (p *pki) updateDocument(epoch uint64) error {
	pkiCtx, cancelFn := context.WithCancel(context.Background())
	go func() {
		select {
		case <-p.HaltCh():
			p.log.Debugf("Terminating gracefully.")
			cancelFn()
		case <-pkiCtx.Done():
		}
	}()

	d, err := p.getDocument(pkiCtx, epoch)
	cancelFn()
	if err != nil {
		p.log.Warnf("Failed to fetch PKI for epoch %v: %v", epoch, err)
		return err
	}
	if !hmac.Equal(d.SphinxGeometryHash, p.c.cfg.SphinxGeometry.Hash()) {
		p.log.Errorf("Sphinx Geometry mismatch is set to: \n %s\n", p.c.cfg.SphinxGeometry.Display())
		panic("Sphinx Geometry mismatch!")
	}
	p.docs.Store(epoch, d)
	return nil
}

func (p *pki) getDocument(ctx context.Context, epoch uint64) (*cpki.Document, error) {
	p.log.Debug("getDocument")
	var d *cpki.Document
	var err error

	p.log.Debugf("Fetching PKI doc for epoch %v from Provider.", epoch)
	resp, err := p.consensusGetter.GetConsensus(ctx, epoch)
	switch err {
	case nil:
	case cpki.ErrNoDocument:
		return nil, err
	default:
		p.log.Infof("Failed to fetch PKI doc for epoch %v from Provider: %v", epoch, err)
		return nil, err
	}

	switch resp.ErrorCode {
	case commands.ConsensusOk:
	case commands.ConsensusGone:
		return nil, cpki.ErrNoDocument
	case commands.ConsensusNotFound:
		return nil, errConsensusNotFound
	default:
		return nil, fmt.Errorf("client/pki: GetConsensus failed: %v", resp.ErrorCode)
	}

	d, err = p.c.PKIClient.Deserialize(resp.Payload)
	if err != nil {
		p.log.Errorf("Failed to deserialize consensus received from provider: %v", err)
		return nil, cpki.ErrNoDocument
	}
	if d.Epoch != epoch {
		p.log.Errorf("BUG: Provider returned document for incorrect epoch: %v", d.Epoch)
		return nil, fmt.Errorf("BUG: Provider returned document for incorrect epoch: %v", d.Epoch)
	}

	return d, err
}

func (p *pki) pruneDocuments(now uint64) {
	p.docs.Range(func(key, value interface{}) bool {
		epoch := key.(uint64)
		if epoch < now {
			p.log.Debugf("Discarding PKI for epoch: %v", epoch)
			p.docs.Delete(epoch)
		}
		if epoch > now+1 {
			p.log.Debugf("Far future PKI document exists, clock ran backwards?: %v", epoch)
		}
		return true
	})
}

func (p *pki) pruneFailures(now uint64) {
	for epoch := range p.failedFetches {
		if epoch < now || epoch > now+1 {
			delete(p.failedFetches, epoch)
		}
	}
}

func (p *pki) start() {
	p.log.Debug("start")
	p.Go(p.worker)
}

func newPKI(c *Client) *pki {
	p := &pki{
		c: c,
		log: log.NewWithOptions(c.logbackend, log.Options{
			Prefix: "client2/pki",
			Level:  log2.ParseLevel(c.cfg.Logging.Level),
		}),
		failedFetches:   make(map[uint64]error),
		forceUpdateCh:   make(chan interface{}, 1),
		consensusGetter: c.conn,
	}

	// Save cached documents
	d := c.cfg.CachedDocument
	if d != nil {
		p.docs.Store(d.Epoch, d)
	}
	return p
}

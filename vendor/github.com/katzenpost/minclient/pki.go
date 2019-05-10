// pki.go - PKI interface.
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

package minclient

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/katzenpost/core/epochtime"
	cpki "github.com/katzenpost/core/pki"
	"github.com/katzenpost/core/wire/commands"
	"github.com/katzenpost/core/worker"
	"gopkg.in/op/go-logging.v1"
)

var (
	errGetConsensusCanceled = errors.New("minclient/pki: consensus fetch canceled")
	errConsensusNotFound    = errors.New("minclient/pki: consensus not ready yet")
	nextFetchTill           = 1 * (epochtime.Period / 8)
	recheckInterval         = 1 * time.Minute
	// WarpedEpoch is a build time flag that accelerates the recheckInterval
	WarpedEpoch             = "false"
)

type pki struct {
	sync.Mutex
	worker.Worker

	c   *Client
	log *logging.Logger

	docs          sync.Map
	failedFetches map[uint64]error
	clockSkew     int64

	forceUpdateCh chan interface{}
}

// ClockSkew returns the current best guess difference between the client's
// system clock and the network's global clock, rounded to the nearest second,
// as measured against the provider during the handshake process.  Calls to
// this routine should not be made until the first `ClientConfig.OnConnFn(true)`
// callback.
func (c *Client) ClockSkew() time.Duration {
	c.pki.Lock()
	defer c.pki.Unlock()

	return time.Duration(c.pki.clockSkew) * time.Second
}

// CurrentDocument returns the current pki.Document, or nil iff one does not
// exist.  The caller MUST NOT modify the returned object in any way.
func (c *Client) CurrentDocument() *cpki.Document {
	return c.pki.currentDocument()
}

func (p *pki) setClockSkew(skew int64) {
	p.log.Debugf("New clock skew: %v sec", skew)
	p.Lock()
	p.clockSkew = skew
	p.Unlock()

	// Wake up the worker if able to.
	select {
	case p.forceUpdateCh <- true:
	default:
	}
}

func (p *pki) skewedUnixTime() int64 {
	if !p.c.cfg.EnableTimeSync {
		return time.Now().Unix()
	}

	p.Lock()
	defer p.Unlock()

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
	const initialSpawnDelay = 5 * time.Second

	timer := time.NewTimer(initialSpawnDelay)
	defer func() {
		p.log.Debug("Halting PKI worker.")
		timer.Stop()
	}()

	pkiCtx, cancelFn := context.WithCancel(context.Background())
	go func() {
		select {
		case <-p.HaltCh():
			cancelFn()
		case <-pkiCtx.Done():
		}
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
			<-timer.C
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

			d, err := p.getDocument(pkiCtx, epoch)
			if err != nil {
				p.log.Warningf("Failed to fetch PKI for epoch %v: %v", epoch, err)
				switch err {
				case cpki.ErrNoDocument:
					p.failedFetches[epoch] = err
				case errGetConsensusCanceled:
					return
				default:
				}
				continue
			}
			p.docs.Store(epoch, d)
			didUpdate = true
		}
		p.pruneFailures(now)
		if didUpdate {
			// Prune documents.
			p.pruneDocuments(now)

			// Kick the connector iff it is waiting on a PKI document.
			if p.c.conn != nil {
				p.c.conn.onPKIFetch()
			}
		}
		if now != lastCallbackEpoch && p.c.cfg.OnDocumentFn != nil {
			if d, ok := p.docs.Load(now); ok {
				lastCallbackEpoch = now
				p.c.cfg.OnDocumentFn(d.(*cpki.Document))
			}
		}

		timer.Reset(recheckInterval)
	}

	// NOTREACHED
}

func (p *pki) getDocument(ctx context.Context, epoch uint64) (*cpki.Document, error) {
	var d *cpki.Document
	var err error

	p.log.Debug("Fetching PKI doc for epoch %v from Provider.", epoch)
	resp, err := p.c.conn.getConsensus(ctx, epoch)
	switch err {
	case nil:
	case cpki.ErrNoDocument:
		return nil, err
	default:
		p.log.Debugf("Failed to fetch PKI doc for epoch %v from Provider: %v", epoch, err)
		return p.getDocumentDirect(ctx, epoch)
	}

	switch resp.ErrorCode {
	case commands.ConsensusOk:
	case commands.ConsensusGone:
		return nil, cpki.ErrNoDocument
	case commands.ConsensusNotFound:
		return nil, errConsensusNotFound
	default:
		return nil, fmt.Errorf("minclient/pki: GetConsensus failed: %v", resp.ErrorCode)
	}

	d, err = p.c.cfg.PKIClient.Deserialize(resp.Payload)
	if err != nil {
		p.log.Errorf("Failed to deserialize consensus received from provider: %v", err)
		return nil, cpki.ErrNoDocument
	}
	if d.Epoch != epoch {
		p.log.Errorf("BUG: Provider returned document for incorrect epoch: %v", d.Epoch)
		return p.getDocumentDirect(ctx, epoch)
	}

	return d, err
}

func (p *pki) getDocumentDirect(ctx context.Context, epoch uint64) (*cpki.Document, error) {
	p.log.Debugf("Fetching PKI doc for epoch %v directly from authority.", epoch)

	d, _, err := p.c.cfg.PKIClient.Get(ctx, epoch)
	select {
	case <-ctx.Done():
		// Canceled mid-fetch.
		return nil, errGetConsensusCanceled
	default:
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
	p.Go(p.worker)
}

func newPKI(c *Client) *pki {
	p := new(pki)
	p.c = c
	p.log = c.cfg.LogBackend.GetLogger("minclient/pki:" + c.displayName)
	p.failedFetches = make(map[uint64]error)
	p.forceUpdateCh = make(chan interface{}, 1)
	return p
}

func init() {
	if WarpedEpoch == "true" {
		recheckInterval = 20 * time.Second
	}
}

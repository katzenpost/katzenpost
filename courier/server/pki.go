// SPDX-FileCopyrightText: © 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"context"
	"crypto/hmac"
	"errors"
	"sync"
	"time"

	"gopkg.in/op/go-logging.v1"

	"github.com/katzenpost/hpqc/kem/schemes"

	vClient "github.com/katzenpost/katzenpost/authority/voting/client"
	vServer "github.com/katzenpost/katzenpost/authority/voting/server"
	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/pki"
	sConstants "github.com/katzenpost/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/katzenpost/core/wire"
	"github.com/katzenpost/katzenpost/core/worker"
	"github.com/katzenpost/katzenpost/replica/common"
)

const NumPKIDocsToFetch = 3

var (
	PublishDeadline     = vServer.PublishConsensusDeadline
	mixServerCacheDelay = epochtime.Period / 16
	nextFetchTill       = epochtime.Period - (PublishDeadline + mixServerCacheDelay)
	recheckInterval     = epochtime.Period / 16
)

type PKIWorker struct {
	worker.Worker

	server *Server
	log    *logging.Logger
	impl   pki.Client

	replicas *common.ReplicaMap

	lock                      *sync.RWMutex
	docs                      map[uint64]*pki.Document
	rawDocs                   map[uint64][]byte
	failedFetches             map[uint64]error
	lastPublishedEpoch        uint64
	lastWarnedEpoch           uint64
	lastPublishedReplicaEpoch uint64
}

func newPKIWorker(server *Server, pkiClient pki.Client, log *logging.Logger) (*PKIWorker, error) {
	p := &PKIWorker{
		server:        server,
		impl:          pkiClient,
		log:           log,
		lock:          new(sync.RWMutex),
		docs:          make(map[uint64]*pki.Document),
		rawDocs:       make(map[uint64][]byte),
		failedFetches: make(map[uint64]error),
		replicas:      common.NewReplicaMap(),
	}

	p.Go(p.worker)

	return p, nil
}

// newPKIWorkerWithDefaultClient creates a PKIWorker with the default voting client
func newPKIWorkerWithDefaultClient(server *Server, log *logging.Logger) (*PKIWorker, error) {
	kemscheme := schemes.ByName(server.cfg.WireKEMScheme)
	if kemscheme == nil {
		return nil, errors.New("kem scheme not found in registry")
	}
	pkiCfg := &vClient.Config{
		KEMScheme:   kemscheme,
		LinkKey:     server.linkPrivKey,
		LogBackend:  server.LogBackend(),
		Authorities: server.cfg.PKI.Voting.Authorities,
		Geo:         server.cfg.SphinxGeometry,
	}

	pkiClient, err := vClient.New(pkiCfg)
	if err != nil {
		return nil, err
	}

	return newPKIWorker(server, pkiClient, log)
}

func (p *PKIWorker) ReplicasCopy() map[[32]byte]*pki.ReplicaDescriptor {
	return p.replicas.Copy()
}

func (p *PKIWorker) documentsToFetch() []uint64 {
	ret := make([]uint64, 0, NumPKIDocsToFetch+1)
	now, _, till := epochtime.Now()
	start := now
	if till < nextFetchTill {
		start = now + 1
	}

	p.lock.RLock()
	defer p.lock.RUnlock()

	for epoch := start; epoch > now-NumPKIDocsToFetch; epoch-- {
		if _, ok := p.docs[epoch]; !ok {
			ret = append(ret, epoch)
		}
	}

	return ret
}

func (p *PKIWorker) getFailedFetch(epoch uint64) (bool, error) {
	p.lock.RLock()
	defer p.lock.RUnlock()
	err, ok := p.failedFetches[epoch]
	return ok, err
}

func (p *PKIWorker) setFailedFetch(epoch uint64, err error) {
	p.lock.Lock()
	defer p.lock.Unlock()
	p.failedFetches[epoch] = err
}

func (p *PKIWorker) pruneFailures() {
	p.lock.Lock()
	defer p.lock.Unlock()

	now, _, _ := epochtime.Now()

	for epoch := range p.failedFetches {
		// Be more aggressive about pruning failures than pruning documents,
		// the worst that can happen is that we query the PKI unneccecarily.
		if epoch < now-(NumPKIDocsToFetch-1) || epoch > now+1 {
			delete(p.failedFetches, epoch)
		}
	}
}

func (p *PKIWorker) pruneDocuments() {
	now, _, _ := epochtime.Now()

	p.lock.Lock()
	defer p.lock.Unlock()
	for epoch := range p.docs {
		if epoch < now-(NumPKIDocsToFetch-1) {
			p.log.Debugf("Discarding PKI for epoch: %v", epoch)
			delete(p.docs, epoch)
			delete(p.rawDocs, epoch)
		}
		if epoch > now+1 {
			// This should NEVER happen.
			p.log.Debugf("Far future PKI document exists, clock ran backwards?: %v", epoch)
		}
	}
}

func (p *PKIWorker) PKIDocument() *pki.Document {
	epoch, _, _ := epochtime.Now()
	return p.entryForEpoch(epoch)
}

func (p *PKIWorker) entryForEpoch(epoch uint64) *pki.Document {
	p.lock.RLock()
	defer p.lock.RUnlock()

	if d, ok := p.docs[epoch]; ok {
		return d
	}
	return nil
}

// ForceFetchPKI forces the PKI worker to fetch a new PKI document for the current epoch.
// This is useful for integration tests where you want to ensure the courier has the latest
// PKI document without waiting for the normal fetch cycle.
func (p *PKIWorker) ForceFetchPKI() error {
	if p.impl == nil {
		return errors.New("no PKI client configured")
	}

	epoch, _, _ := epochtime.Now()

	// Clear any failed fetch record for this epoch to allow retry
	p.lock.Lock()
	delete(p.failedFetches, epoch)
	p.lock.Unlock()

	p.log.Debugf("Force fetching PKI document for epoch %v", epoch)

	// Fetch the PKI document
	ctx := context.Background()
	d, rawDoc, err := p.impl.Get(ctx, epoch)
	if err != nil {
		p.log.Warningf("Force fetch failed for epoch %v: %v", epoch, err)
		return err
	}

	// Validate sphinx geometry
	if !hmac.Equal(d.SphinxGeometryHash, p.server.cfg.SphinxGeometry.Hash()) {
		return errors.New("sphinx geometry mismatch")
	}

	// Update replicas and store the document
	p.replicas.UpdateFromPKIDoc(d)

	p.lock.Lock()
	p.rawDocs[epoch] = rawDoc
	p.docs[epoch] = d
	p.lock.Unlock()

	p.log.Debugf("Successfully force fetched PKI document for epoch %v", epoch)

	// Kick the connector to update connections
	p.server.connector.ForceUpdate()

	return nil
}

// HasCurrentPKIDocument returns true if the courier has a PKI document for the current epoch.
// This is useful for integration tests to check if the courier is ready.
func (p *PKIWorker) HasCurrentPKIDocument() bool {
	epoch, _, _ := epochtime.Now()
	return p.entryForEpoch(epoch) != nil
}

// updateTimer is used by the worker loop to determine when next to wake and fetch.
func (p *PKIWorker) updateTimer(timer *time.Timer) {
	now, elapsed, till := epochtime.Now()
	p.log.Debugf("pki woke %v into epoch %v with %v remaining", elapsed, now, till)

	// it's after the consensus publication deadline
	if elapsed > vServer.PublishConsensusDeadline {
		p.log.Debugf("After deadline for next epoch publication")
		if p.entryForEpoch(now+1) == nil {
			p.log.Debugf("no document for %v yet, reset to %v", now+1, recheckInterval)
			timer.Reset(recheckInterval)
		} else {
			interval := till
			p.log.Debugf("document cached for %v, reset to %v", now+1, interval)
			timer.Reset(interval)
		}
	} else {
		p.log.Debugf("Not yet time for next epoch publication")
		// no document for current epoch
		if p.entryForEpoch(now) == nil {
			p.log.Debugf("no document cached for current epoch %v, reset to %v", now, recheckInterval)
			timer.Reset(recheckInterval)
		} else {
			interval := vServer.PublishConsensusDeadline - elapsed
			p.log.Debugf("Document cached for current epoch %v, reset to %v", now, recheckInterval)
			timer.Reset(interval)
		}
	}
}

func (p *PKIWorker) worker() {
	p.log.Info("PKI worker started")

	timer, pkiCtx, isCanceled, lastUpdateEpoch := p.initializeWorker()
	if timer == nil {
		return // No implementation configured
	}
	defer func() {
		p.log.Debugf("Halting PKI worker.")
		timer.Stop()
	}()

	p.runMainLoop(timer, pkiCtx, isCanceled, &lastUpdateEpoch)
}

// initializeWorker sets up the PKI worker context and timer
func (p *PKIWorker) initializeWorker() (*time.Timer, context.Context, func() bool, uint64) {
	var initialSpawnDelay = epochtime.Period / 64
	timer := time.NewTimer(initialSpawnDelay)

	if p.impl == nil {
		p.log.Warningf("No implementation is configured, disabling PKI interface.")
		return nil, nil, nil, 0
	}

	pkiCtx, cancelFn := context.WithCancel(context.Background())
	go func() {
		select {
		case <-p.HaltCh():
			cancelFn()
		case <-pkiCtx.Done():
			p.log.Debug("<-pkiCtx.Done()")
		}
	}()

	isCanceled := func() bool {
		select {
		case <-pkiCtx.Done():
			return true
		default:
			return false
		}
	}

	return timer, pkiCtx, isCanceled, 0
}

// runMainLoop handles the main PKI worker event loop
func (p *PKIWorker) runMainLoop(timer *time.Timer, pkiCtx context.Context, isCanceled func() bool, lastUpdateEpoch *uint64) {
	for {
		if !p.handleTimerEvent(timer, pkiCtx) {
			return
		}

		didUpdate := p.fetchDocuments(pkiCtx, isCanceled)
		p.processDocuments(didUpdate)
		p.updateCurrentEpoch(lastUpdateEpoch)
		p.updateTimer(timer)
	}
}

// handleTimerEvent processes timer and cancellation events
func (p *PKIWorker) handleTimerEvent(timer *time.Timer, pkiCtx context.Context) bool {
	var timerFired bool
	select {
	case <-p.HaltCh():
		p.log.Debug("Terminating gracefully.")
		return false
	case <-pkiCtx.Done():
		p.log.Debug("pkiCtx.Done")
		return false
	case <-timer.C:
		timerFired = true
	}

	if !timerFired && !timer.Stop() {
		select {
		case <-p.HaltCh():
			p.log.Debug("Terminating gracefully.")
			return false
		case <-timer.C:
		}
	}
	return true
}

// fetchDocuments fetches PKI documents for required epochs
func (p *PKIWorker) fetchDocuments(pkiCtx context.Context, isCanceled func() bool) bool {
	var didUpdate bool
	for _, epoch := range p.documentsToFetch() {
		p.log.Debugf("PKI worker, documentsToFetch epoch %d", epoch)

		// Certain errors in fetching documents are treated as hard
		// failures that suppress further attempts to fetch the document
		// for the epoch.
		if ok, err := p.getFailedFetch(epoch); ok {
			p.log.Debugf("Skipping fetch for epoch %v: %v", epoch, err)
			continue
		}

		d, rawDoc, err := p.impl.Get(pkiCtx, epoch)
		if isCanceled() {
			// Canceled mid-fetch.
			p.log.Debug("Canceled mid-fetch")
			return false
		}
		if err != nil {
			p.log.Warningf("Failed to fetch PKI for epoch %v: %v", epoch, err)
			if err == pki.ErrDocumentGone {
				p.setFailedFetch(epoch, err)
			}
			continue
		}

		p.lock.Lock()
		p.rawDocs[epoch] = rawDoc
		p.docs[epoch] = d
		p.lock.Unlock()
		didUpdate = true
		p.replicas.UpdateFromPKIDoc(d)
	}
	return didUpdate
}

// processDocuments handles document cleanup and pruning
func (p *PKIWorker) processDocuments(didUpdate bool) {
	p.pruneFailures()
	if didUpdate {
		// Dispose of the old PKI documents.
		p.pruneDocuments()
	}
}

// updateCurrentEpoch updates components when a new epoch document is available
func (p *PKIWorker) updateCurrentEpoch(lastUpdateEpoch *uint64) {
	// Internal component depend on network wide paramemters, and or the
	// list of nodes.  Update if there is a new document for the current
	// epoch.
	if now, _, _ := epochtime.Now(); now != *lastUpdateEpoch {
		if doc := p.entryForEpoch(now); doc != nil {
			*lastUpdateEpoch = now
		}
	}
}

func (p *PKIWorker) AuthenticateReplicaConnection(c *wire.PeerCredentials) (*pki.ReplicaDescriptor, bool) {
	if len(c.AdditionalData) != sConstants.NodeIDLength {
		p.log.Debugf("AuthenticateConnection: '%x' AD not an IdentityKey?.", c.AdditionalData)
		return nil, false
	}
	var nodeID [sConstants.NodeIDLength]byte
	copy(nodeID[:], c.AdditionalData)
	replicaDesc, isReplica := p.replicas.GetReplicaDescriptor(&nodeID)
	if !isReplica {
		return nil, false
	}
	blob, err := c.PublicKey.MarshalBinary()
	if err != nil {
		panic(err)
	}
	if !hmac.Equal(replicaDesc.LinkKey, blob) {
		return nil, false
	}
	return replicaDesc, true
}

// SetDocumentForEpoch sets a PKI document for a specific epoch; for testing only.
func (p *PKIWorker) SetDocumentForEpoch(epoch uint64, doc *pki.Document, rawDoc []byte) {
	p.lock.Lock()
	defer p.lock.Unlock()
	p.docs[epoch] = doc
	p.rawDocs[epoch] = rawDoc
	p.replicas.UpdateFromPKIDoc(doc)
}

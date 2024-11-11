// SPDX-FileCopyrightText: Copyright (C) 2017  Yawning Angel.
// SPDX-License-Identifier: AGPL-3.0-only

package replica

import (
	"context"
	"crypto/hmac"
	"fmt"
	"time"

	vServer "github.com/katzenpost/katzenpost/authority/voting/server"
	"github.com/katzenpost/katzenpost/core/epochtime"
	cpki "github.com/katzenpost/katzenpost/core/pki"
)

const NumPKIDocsToFetch = 3

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

func (p *PKIWorker) PKIDocument() *cpki.Document {
	epoch, _, _ := epochtime.Now()
	return p.entryForEpoch(epoch)
}

func (p *PKIWorker) entryForEpoch(epoch uint64) *cpki.Document {
	p.lock.RLock()
	defer p.lock.RUnlock()

	if d, ok := p.docs[epoch]; ok {
		return d
	}
	return nil
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
	var initialSpawnDelay = epochtime.Period / 64

	timer := time.NewTimer(initialSpawnDelay)
	defer func() {
		p.log.Debugf("Halting PKI worker.")
		timer.Stop()
	}()

	if p.impl == nil {
		p.log.Warningf("No implementation is configured, disabling PKI interface.")
		return
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

	// Note: The worker's start is delayed till after the Server's connector
	// is initialized, so that force updating the outgoing connection table
	// is guaranteed to work.

	var lastUpdateEpoch uint64

	for {
		var timerFired bool
		select {
		case <-p.HaltCh():
			p.log.Debug("Terminating gracefully.")
			return
		case <-pkiCtx.Done():
			p.log.Debug("pkiCtx.Done")
			return
		case <-timer.C:
			timerFired = true
		}
		if !timerFired && !timer.Stop() {
			select {
			case <-p.HaltCh():
				p.log.Debug("Terminating gracefully.")
				return
			case <-timer.C:
			}
		}

		// Check to see if we need to publish the descriptor, and do so, along
		// with all the key rotation bits.
		err := p.publishDescriptorIfNeeded(pkiCtx)
		if isCanceled() {
			// Canceled mid-post
			p.log.Debug("Canceled mid-post")
			return
		}
		if err != nil {
			p.log.Warningf("Failed to post to PKI: %v", err)
		}
		// Fetch the PKI documents as required.
		var didUpdate bool
		for _, epoch := range p.documentsToFetch() {
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
				return
			}
			if err != nil {
				p.log.Warningf("Failed to fetch PKI for epoch %v: %v", epoch, err)
				if err == cpki.ErrDocumentGone {
					p.setFailedFetch(epoch, err)
				}
				continue
			}

			if !hmac.Equal(d.SphinxGeometryHash, p.server.cfg.SphinxGeometry.Hash()) {
				p.log.Errorf("Sphinx Geometry mismatch is set to: \n %s\n", p.server.cfg.SphinxGeometry.Display())
				panic("Sphinx Geometry mismatch!")
			}

			// take note of the service nodes and storage replicas
			p.updateReplicas(d)

			p.lock.Lock()
			p.rawDocs[epoch] = rawDoc
			p.docs[epoch] = d
			p.lock.Unlock()
			didUpdate = true
		}

		p.pruneFailures()
		if didUpdate {
			// Dispose of the old PKI documents.
			p.pruneDocuments()

			// If the PKI document map changed, kick the connector worker.
			p.server.connector.ForceUpdate()
		}

		// Internal component depend on network wide paramemters, and or the
		// list of nodes.  Update if there is a new document for the current
		// epoch.
		if now, _, _ := epochtime.Now(); now != lastUpdateEpoch {
			if doc := p.entryForEpoch(now); doc != nil {
				lastUpdateEpoch = now
			}
		}
		p.updateTimer(timer)
	}
}

func (p *PKIWorker) publishDescriptorIfNeeded(pkiCtx context.Context) error {
	p.log.Debug("publishing replica descriptor")
	epoch, _, till := epochtime.Now()
	doPublishEpoch := uint64(0)
	switch p.lastPublishedEpoch {
	case 0:
		// Initial startup.  Regardless of the deadline, publish.
		p.log.Debugf("Initial startup or correcting for time jump.")
		doPublishEpoch = epoch
	case epoch:
		// Check the deadline for the next publication time.
		if till > PublishDeadline {
			p.log.Debugf("Within the publication time for epoch: %v", epoch+1)
			doPublishEpoch = epoch + 1
			break
		}

		// Well, we appeared to have missed the publication deadline for the
		// next epoch, so give up till the transition.
		if p.lastWarnedEpoch != epoch {
			// Debounce this so we don't spam the log.
			p.lastWarnedEpoch = epoch
			return fmt.Errorf("missed publication deadline for epoch: %v", epoch+1)
		}
		return nil
	case epoch + 1:
		// The next epoch has been published.
		return nil
	default:
		// What the fuck?  The last descriptor that we published is a time
		// that we don't recognize.  The system's civil time probably jumped,
		// even though the assumption is that all nodes run NTP.
		p.log.Warningf("Last published epoch %v is wildly disjointed from %v.", p.lastPublishedEpoch, epoch)

		// I don't even know what the sane thing to do here is, just treat it
		// as if the node's just started and publish for the current I guess.
		doPublishEpoch = epoch
	}

	// Note: Why, yes I *could* cache the descriptor and save a trivial amount
	// of time and CPU, but this is invoked infrequently enough that it's
	// probably not worth it.

	// Generate the non-key parts of the descriptor.
	linkblob, err := p.server.linkKey.Public().MarshalBinary()
	if err != nil {
		return err
	}
	idkeyblob, err := p.server.identityPublicKey.MarshalBinary()
	if err != nil {
		return err
	}

	// handle the replica NIKE keys
	replicaEpoch, _, _ := ReplicaNow()
	envelopeKeys := make(map[uint64][]byte)

	key1, err := p.server.envelopeKeys.EnsureKey(replicaEpoch)
	if err != nil {
		return err
	}
	key2, err := p.server.envelopeKeys.EnsureKey(replicaEpoch + 1)
	if err != nil {
		return err
	}

	envelopeKeys[replicaEpoch] = key1.PublicKey.Bytes()
	envelopeKeys[replicaEpoch+1] = key2.PublicKey.Bytes()

	desc := &cpki.ReplicaDescriptor{
		Name:         p.server.cfg.Identifier,
		IdentityKey:  idkeyblob,
		LinkKey:      linkblob,
		Addresses:    p.descAddrMap,
		EnvelopeKeys: envelopeKeys,
	}

	// XXX FIXME: we need a replica NIKE key to publish
	desc.EnvelopeKeys = make(map[uint64][]byte)

	// Post the descriptor to all the authorities.
	err = p.impl.PostReplica(pkiCtx, doPublishEpoch, p.server.identityPrivateKey, p.server.identityPublicKey, desc)
	switch err {
	case nil:
		p.log.Debugf("Posted descriptor for epoch: %v", doPublishEpoch)
		p.lastPublishedEpoch = doPublishEpoch
	case cpki.ErrInvalidPostEpoch:
		// Treat this class (conflict/late descriptor) as a permanent rejection
		// and suppress further uploads.
		p.log.Warningf("Authority rejected upload for epoch: %v (Conflict/Late)", doPublishEpoch)
		p.lastPublishedEpoch = doPublishEpoch
	default:
		// XXX: the voting authority implementation does not return any of the above error types...
		// and the storage replica will continue to fail to submit the same descriptor repeatedly.
		p.lastPublishedEpoch = doPublishEpoch
	}

	return err
}

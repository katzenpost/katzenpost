// SPDX-FileCopyrightText: Copyright (C) 2017  Yawning Angel.
// SPDX-License-Identifier: AGPL-3.0-only

package replica

import (
	"context"
	"crypto/hmac"
	"time"

	replicaCommon "github.com/katzenpost/katzenpost/replica/common"

	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/pki"
	cpki "github.com/katzenpost/katzenpost/core/pki"
)

const NumPKIDocsToFetch = 3

// PKIDocument returns the PKI document for the current epoch
func (p *PKIWorker) PKIDocument() *cpki.Document {
	epoch, _, _ := epochtime.Now()
	return p.entryForEpoch(epoch)
}

// entryForEpoch returns the PKI document for the specified epoch
func (p *PKIWorker) entryForEpoch(epoch uint64) *cpki.Document {
	return p.EntryForEpoch(epoch)
}

func (p *PKIWorker) worker() {
	var initialSpawnDelay = epochtime.Period / 64
	timer := time.NewTimer(initialSpawnDelay)
	defer timer.Stop()

	if p.impl == nil {
		p.GetLogger().Warningf("No PKI client is configured, disabling PKI interface.")
		return
	}

	pkiCtx, cancelFn, isCanceled := pki.SetupWorkerContext(p.HaltCh(), p.GetLogger())
	defer cancelFn()

	var lastUpdateEpoch uint64

	for {
		if !pki.HandleTimerEvent(timer, pkiCtx, p.HaltCh(), p.GetLogger()) {
			return
		}

		// Check to see if we need to publish the descriptor
		err := p.publishDescriptorIfNeeded(pkiCtx)
		if isCanceled() {
			p.GetLogger().Debug("Canceled mid-post")
			return
		}
		if err != nil {
			p.GetLogger().Warningf("Failed to post to PKI: %v", err)
		}

		// Fetch and process PKI documents
		didUpdate := p.fetchAndProcessDocuments(pkiCtx, isCanceled)
		if isCanceled() {
			return
		}

		// Handle document updates and cleanup
		p.handleDocumentUpdates(didUpdate)

		// Update epoch tracking
		lastUpdateEpoch = p.updateEpochTracking(lastUpdateEpoch)

		p.UpdateTimer(timer)
	}
}

// fetchAndProcessDocuments fetches PKI documents and processes them
func (p *PKIWorker) fetchAndProcessDocuments(pkiCtx context.Context, isCanceled func() bool) bool {
	results := p.FetchDocuments(pkiCtx, isCanceled)
	if len(results) == 0 {
		return false
	}

	var didUpdate bool
	for _, result := range results {
		if result.Skipped || result.Error != nil {
			continue
		}

		// Validate sphinx geometry
		if !hmac.Equal(result.Doc.SphinxGeometryHash, p.server.cfg.SphinxGeometry.Hash()) {
			p.GetLogger().Errorf("Sphinx Geometry mismatch is set to: \n %s\n", p.server.cfg.SphinxGeometry.Display())
			panic("Sphinx Geometry mismatch!")
		}

		// take note of the service nodes and storage replicas
		p.updateReplicas(result.Doc)

		p.StoreDocument(result.Epoch, result.Doc, result.RawDoc)
		didUpdate = true
	}
	return didUpdate
}

// handleDocumentUpdates handles cleanup and updates when documents change
func (p *PKIWorker) handleDocumentUpdates(didUpdate bool) {
	p.PruneFailures()
	if didUpdate {
		// Dispose of the old PKI documents.
		p.PruneDocuments()

		// If the PKI document map changed, kick the connector worker.
		p.server.connector.ForceUpdate()
	}
}

// updateEpochTracking updates epoch tracking and returns the new lastUpdateEpoch
func (p *PKIWorker) updateEpochTracking(lastUpdateEpoch uint64) uint64 {
	// Internal component depend on network wide paramemters, and or the
	// list of nodes.  Update if there is a new document for the current
	// epoch.
	if now, _, _ := epochtime.Now(); now != lastUpdateEpoch {
		if doc := p.entryForEpoch(now); doc != nil {
			return now
		}
	}
	return lastUpdateEpoch
}

func (p *PKIWorker) publishDescriptorIfNeeded(pkiCtx context.Context) error {
	// Skip publishing if we don't have a real PKI client (mock mode)
	if p.impl == nil {
		return nil
	}

	epoch, elapsed, _ := epochtime.Now()
	doPublishEpoch := uint64(0)
	if p.lastPublishedEpoch > epoch {
		p.GetLogger().Debugf("publishDescriptorIfNeeded: not needed (published: %d current: %d)", p.lastPublishedEpoch, epoch)
		return nil
	}
	if p.lastPublishedEpoch == 0 {
		doPublishEpoch = epoch
		// Check the deadline for the next publication time:
	} else if elapsed < PublishDeadline {
		p.GetLogger().Debugf("Within the publication time for epoch: %v", epoch+1)
		doPublishEpoch = epoch
		if p.lastPublishedEpoch == epoch {
			doPublishEpoch = epoch + 1
		}
	} else {
		doPublishEpoch = epoch + 1
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
	replicaEpoch, _, _ := replicaCommon.ReplicaNow()
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
		Epoch:        doPublishEpoch,
		IdentityKey:  idkeyblob,
		LinkKey:      linkblob,
		Addresses:    p.descAddrMap,
		EnvelopeKeys: envelopeKeys,
	}

	// Post the descriptor to all the authorities.
	p.GetLogger().Debug("publishing replica descriptor")
	err = p.impl.PostReplica(pkiCtx, doPublishEpoch, p.server.identityPrivateKey, p.server.identityPublicKey, desc)
	switch err {
	case nil:
		p.GetLogger().Debugf("Posted descriptor for epoch: %v", doPublishEpoch)
		p.lastPublishedEpoch = doPublishEpoch
	case cpki.ErrInvalidPostEpoch:
		// Treat this class (conflict/late descriptor) as a permanent rejection
		// and suppress further uploads.
		p.GetLogger().Warningf("Authority rejected upload for epoch: %v (Conflict/Late)", doPublishEpoch)
		p.lastPublishedEpoch = doPublishEpoch
	default:
		// the voting authority implementation does not return any of the above error types...
		// and the storage replica will continue to fail to submit the same descriptor repeatedly.
		p.lastPublishedEpoch = doPublishEpoch
	}

	return err
}

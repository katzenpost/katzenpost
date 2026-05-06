// SPDX-FileCopyrightText: Copyright (C) 2017  Yawning Angel.
// SPDX-License-Identifier: AGPL-3.0-only

package replica

import (
	"context"
	"crypto/hmac"
	"errors"
	"fmt"
	"strconv"
	"time"

	replicaCommon "github.com/katzenpost/katzenpost/replica/common"

	"github.com/katzenpost/katzenpost/core/epochtime"
	cpki "github.com/katzenpost/katzenpost/core/pki"
)

const (
	NumPKIDocsToFetch      = 3
	descriptorUploadSafety = 10 * time.Second
)

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

	pkiCtx, cancelFn, isCanceled := cpki.SetupWorkerContext(p.HaltCh(), p.GetLogger())
	defer cancelFn()

	var lastUpdateEpoch uint64

	for {
		if !cpki.HandleTimerEvent(timer, pkiCtx, p.HaltCh(), p.GetLogger()) {
			return
		}

		now, elapsed, till := epochtime.Now()
		p.GetLogger().Debugf(
			"REPLICA PKI WORKER: wake epoch=%d elapsed=%v remaining=%v; checking descriptor upload before PKI document fetch",
			now,
			elapsed,
			till,
		)

		// Check to see if we need to publish the descriptor
		//
		// Descriptor upload is best-effort for the selected publication epoch.
		// A closed upload window, transient upload failure, or permanent upload
		// rejection must not suppress PKI document fetches for the current epoch.
		err := p.publishDescriptorIfNeeded(pkiCtx)
		if isCanceled() {
			p.GetLogger().Debug("Canceled mid-post")
			return
		}
		if err != nil {
			p.GetLogger().Warningf("REPLICA DESCRIPTOR UPLOAD: failed to post to PKI; continuing with PKI document fetch: %v", err)
		}

		p.GetLogger().Debug("REPLICA PKI WORKER: descriptor upload check complete; fetching PKI documents if needed")

		// Fetch and process PKI documents
		//
		// Fetching continues even when descriptor upload was skipped or failed.
		// This keeps connector/authentication state fresh for late starts after
		// the descriptor upload window has closed.
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
		p.GetLogger().Debug("REPLICA PKI FETCH: no PKI documents needed this cycle")
		return false
	}

	var didUpdate bool
	var stored, skipped, failed int

	for _, result := range results {
		if result.Skipped {
			skipped++
			p.GetLogger().Debugf("REPLICA PKI FETCH: skipped epoch=%d: %v", result.Epoch, result.Error)
			continue
		}
		if result.Error != nil {
			failed++
			p.GetLogger().Debugf("REPLICA PKI FETCH: failed epoch=%d: %v", result.Epoch, result.Error)
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
		stored++
		didUpdate = true
	}

	p.GetLogger().Debugf(
		"REPLICA PKI FETCH: cycle complete results=%d stored=%d skipped=%d failed=%d did_update=%v",
		len(results),
		stored,
		skipped,
		failed,
		didUpdate,
	)

	if didUpdate {
		p.GetLogger().Noticef(
			"REPLICA PKI FETCH: stored %d PKI document(s); connector/authentication state will be refreshed",
			stored,
		)
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

	currentEpoch, elapsed, till := epochtime.Now()

	// Voting for doc[N] happens during epoch N-1, so a descriptor uploaded
	// during the current epoch must claim epoch = currentEpoch + 1 to be
	// included in the document the dirauths are about to sign.
	doPublishEpoch := currentEpoch + 1

	if p.lastPublishedEpoch >= doPublishEpoch {
		p.GetLogger().Debugf(
			"REPLICA DESCRIPTOR UPLOAD: not needed; already published target epoch published=%d target=%d current_epoch=%d; PKI document fetch will continue",
			p.lastPublishedEpoch,
			doPublishEpoch,
			currentEpoch,
		)
		return nil
	}

	uploadDeadline := PublishDeadline - descriptorUploadSafety
	if uploadDeadline < 0 {
		uploadDeadline = PublishDeadline
	}

	budget := uploadDeadline - elapsed
	if budget <= 0 {
		p.GetLogger().Noticef(
			"REPLICA DESCRIPTOR UPLOAD: not posting descriptor for epoch=%d current_epoch=%d elapsed=%v deadline=%v safety=%v remaining=%v: upload window closed; skipping descriptor upload only; PKI document fetch will continue",
			doPublishEpoch,
			currentEpoch,
			elapsed,
			PublishDeadline,
			descriptorUploadSafety,
			till,
		)
		return nil
	}

	p.GetLogger().Noticef(
		"REPLICA DESCRIPTOR UPLOAD: selected upload epoch=%d current_epoch=%d elapsed=%v deadline=%v safety=%v budget=%v",
		doPublishEpoch,
		currentEpoch,
		elapsed,
		PublishDeadline,
		descriptorUploadSafety,
		budget,
	)

	uploadCtx, cancel := context.WithTimeout(pkiCtx, budget)
	defer cancel()

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
		ReplicaID:    p.server.cfg.ReplicaID,
		Epoch:        doPublishEpoch,
		IdentityKey:  idkeyblob,
		LinkKey:      linkblob,
		Addresses:    p.descAddrMap,
		EnvelopeKeys: envelopeKeys,
	}

	if err := cpki.IsReplicaDescriptorWellFormed(desc, doPublishEpoch); err != nil {
		p.GetLogger().Noticef(
			"REPLICA DESCRIPTOR UPLOAD: refusing to send malformed replica descriptor %s for epoch %d: %s",
			strconv.QuoteToASCII(desc.Name),
			doPublishEpoch,
			strconv.QuoteToASCII(err.Error()),
		)
		return fmt.Errorf("refusing to send malformed replica descriptor for epoch %d: %w", doPublishEpoch, err)
	}

	// Post the descriptor to all the authorities.
	p.GetLogger().Noticef(
		"REPLICA DESCRIPTOR UPLOAD: attempting to upload replica descriptor %s for epoch %d",
		strconv.QuoteToASCII(desc.Name),
		doPublishEpoch,
	)

	err = p.impl.PostReplica(uploadCtx, doPublishEpoch, p.server.identityPrivateKey, p.server.identityPublicKey, desc)
	switch {
	case err == nil:
		p.GetLogger().Noticef(
			"REPLICA DESCRIPTOR UPLOAD: successfully posted replica descriptor %s for epoch %d",
			strconv.QuoteToASCII(desc.Name),
			doPublishEpoch,
		)
		p.lastPublishedEpoch = doPublishEpoch

	case errors.Is(err, cpki.ErrInvalidPostEpoch):
		// Treat this class (conflict/late descriptor) as a permanent rejection
		// and suppress further uploads.
		p.GetLogger().Warningf(
			"REPLICA DESCRIPTOR UPLOAD: authority permanently rejected replica descriptor %s upload for epoch %d; advancing past this epoch: %s",
			strconv.QuoteToASCII(desc.Name),
			doPublishEpoch,
			strconv.QuoteToASCII(err.Error()),
		)
		p.lastPublishedEpoch = doPublishEpoch

	default:
		// the voting authority implementation does not return any of the above error types...
		// and the storage replica will continue to fail to submit the same descriptor repeatedly.
		p.GetLogger().Warningf(
			"REPLICA DESCRIPTOR UPLOAD: failed to upload replica descriptor %s for epoch %d; PKI document fetch will continue: %s",
			strconv.QuoteToASCII(desc.Name),
			doPublishEpoch,
			strconv.QuoteToASCII(err.Error()),
		)
	}

	return err
}

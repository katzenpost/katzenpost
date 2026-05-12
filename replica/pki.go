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

type postReplicaAcceptedAuthoritiesProvider interface {
	LastPostReplicaAcceptedAuthorities(epoch uint64) []string
}

func postReplicaAcceptedAuthorities(impl interface{}, epoch uint64) []string {
	provider, ok := impl.(postReplicaAcceptedAuthoritiesProvider)
	if !ok {
		return nil
	}

	acceptedBy := provider.LastPostReplicaAcceptedAuthorities(epoch)
	if len(acceptedBy) == 0 {
		return nil
	}
	return acceptedBy
}

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
	timer := time.NewTimer(0)
	defer timer.Stop()

	if p.impl == nil {
		p.GetLogger().Warningf("No PKI client is configured, disabling PKI interface.")
		return
	}

	pkiCtx, cancelFn, isCanceled := cpki.SetupWorkerContext(p.HaltCh(), p.GetLogger())
	defer cancelFn()

	var lastUpdateEpoch uint64

	for {
		select {
		case <-p.HaltCh():
			return
		case <-timer.C:
		}

		currentEpoch, elapsed, till := epochtime.Now()
		p.GetLogger().Debugf(
			"REPLICA PKI WORKER: wake current_epoch=%d elapsed=%v remaining=%v",
			currentEpoch,
			elapsed,
			till,
		)

		// Check to see if we need to publish the descriptor first.
		//
		// Descriptor upload is time-sensitive and must happen during the
		// authority descriptor upload phase. A restarted replica may begin this
		// worker with little upload-window budget remaining. Do not spend that
		// budget fetching PKI documents before attempting descriptor publication.
		//
		// A closed upload window, transient upload failure, or permanent upload
		// rejection must not suppress future PKI document fetches.
		err := p.publishDescriptorIfNeeded(pkiCtx)
		if isCanceled() {
			p.GetLogger().Debug("Canceled mid-post")
			return
		}
		if err != nil {
			p.GetLogger().Warningf("REPLICA DESCRIPTOR UPLOAD: failed to post to PKI; continuing with PKI document fetch: %v", err)
		}

		p.GetLogger().Debug("REPLICA PKI WORKER: descriptor upload check complete; fetching PKI documents if needed")

		// Fetch and process PKI documents.
		//
		// Fetching continues even when descriptor upload was skipped or failed.
		// This keeps connector/authentication state fresh for late starts after
		// the descriptor upload window has closed.
		didUpdate := p.fetchAndProcessDocuments(pkiCtx, isCanceled)
		if isCanceled() {
			return
		}

		// Handle document updates and cleanup.
		p.handleDocumentUpdates(didUpdate)

		// Update epoch tracking.
		lastUpdateEpoch = p.updateEpochTracking(lastUpdateEpoch)

		p.updateTimer(timer)
	}
}

// fetchAndProcessDocuments fetches PKI documents and processes them.
func (p *PKIWorker) fetchAndProcessDocuments(pkiCtx context.Context, isCanceled func() bool) bool {
	results := p.FetchDocuments(pkiCtx, isCanceled)
	if len(results) == 0 {
		return false
	}

	didUpdate := false
	for _, result := range results {
		if result.Skipped || result.Error != nil {
			continue
		}

		// Validate sphinx geometry.
		if !hmac.Equal(result.Doc.SphinxGeometryHash, p.server.cfg.SphinxGeometry.Hash()) {
			p.GetLogger().Errorf("Sphinx Geometry mismatch is set to: \n %s\n", p.server.cfg.SphinxGeometry.Display())
			panic("Sphinx Geometry mismatch!")
		}

		// Take note of the service nodes and storage replicas.
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

// updateTimer is used by the replica PKI worker loop to determine when to
// wake next.
//
// This intentionally does not use the generic core/pki WorkerBase.UpdateTimer
// directly while the descriptor upload window is open. Storage replicas need
// to publish their replica descriptor during the authority descriptor upload
// phase. If they already have a current PKI document, the generic worker timer
// can otherwise sleep until the consensus-publication side of the epoch, which
// is too late for descriptor upload.
func (p *PKIWorker) updateTimer(timer *time.Timer) {
	now, elapsed, till := epochtime.Now()

	uploadDeadline := PublishDeadline - descriptorUploadSafety
	if uploadDeadline < 0 {
		uploadDeadline = PublishDeadline
	}

	p.GetLogger().Debugf(
		"REPLICA PKI WORKER: timer update epoch=%d elapsed=%v remaining=%v deadline=%v safety=%v published_epoch=%d",
		now,
		elapsed,
		till,
		PublishDeadline,
		descriptorUploadSafety,
		p.lastPublishedEpoch,
	)

	// While the upload window is open, wake promptly until we have posted at
	// least the current epoch and, if possible, the next epoch. This matches the
	// storage replica publication strategy in publishDescriptorIfNeeded:
	//
	//   - if lastPublishedEpoch < currentEpoch: publish currentEpoch
	//   - if lastPublishedEpoch == currentEpoch: publish currentEpoch + 1
	//   - if lastPublishedEpoch > currentEpoch: descriptor publication is done
	//
	// This also gives transient PostReplica failures a chance to retry before
	// the authority upload window closes.
	if elapsed < uploadDeadline && p.lastPublishedEpoch <= now {
		interval := time.Second
		remainingUpload := uploadDeadline - elapsed
		if remainingUpload < interval {
			interval = remainingUpload
		}
		if interval <= 0 {
			interval = time.Second
		}
		p.GetLogger().Debugf("REPLICA PKI WORKER: upload window open, reset to %v", interval)
		timer.Reset(interval)
		return
	}

	// Once the upload window is closed, do not spin inside the same epoch just
	// to log another skipped descriptor upload. Wake at the next epoch boundary,
	// where the next upload window opens.
	if elapsed >= uploadDeadline {
		interval := till
		if interval < time.Second {
			interval = time.Second
		}
		p.GetLogger().Debugf("REPLICA PKI WORKER: upload window closed, reset to next epoch in %v", interval)
		timer.Reset(interval)
		return
	}

	p.UpdateTimer(timer)
}

func (p *PKIWorker) publishDescriptorIfNeeded(pkiCtx context.Context) error {
	// Skip publishing if we don't have a real PKI client (mock mode).
	if p.impl == nil {
		p.GetLogger().Debug("No PKI client configured, skipping descriptor publication")
		return nil
	}

	currentEpoch, elapsed, till := epochtime.Now()

	uploadDeadline := PublishDeadline - descriptorUploadSafety
	if uploadDeadline < 0 {
		uploadDeadline = PublishDeadline
	}

	if elapsed >= uploadDeadline {
		p.GetLogger().Noticef(
			"REPLICA DESCRIPTOR UPLOAD: not posting descriptor current_epoch=%d elapsed=%v deadline=%v safety=%v remaining=%v: upload window closed; skipping descriptor upload only; PKI document fetch will continue",
			currentEpoch,
			elapsed,
			PublishDeadline,
			descriptorUploadSafety,
			till,
		)
		return nil
	}

	doPublishEpoch := currentEpoch + 1
	uploadReason := "prepublishing next epoch while descriptor upload window remains open"

	if p.lastPublishedEpoch >= doPublishEpoch {
		p.GetLogger().Debugf(
			"REPLICA DESCRIPTOR UPLOAD: not needed; already published target epoch published=%d target=%d current_epoch=%d elapsed=%v",
			p.lastPublishedEpoch,
			doPublishEpoch,
			currentEpoch,
			elapsed,
		)
		return nil
	}

	budget := uploadDeadline - elapsed
	if budget <= 0 {
		p.GetLogger().Noticef(
			"REPLICA DESCRIPTOR UPLOAD: not posting descriptor current_epoch=%d publish_epoch=%d elapsed=%v deadline=%v safety=%v remaining=%v: no upload budget remains",
			currentEpoch,
			doPublishEpoch,
			elapsed,
			PublishDeadline,
			descriptorUploadSafety,
			till,
		)
		return nil
	}

	p.GetLogger().Noticef(
		"REPLICA DESCRIPTOR UPLOAD: selected upload epoch=%d current_epoch=%d elapsed=%v deadline=%v safety=%v budget=%v reason=%s",
		doPublishEpoch,
		currentEpoch,
		elapsed,
		PublishDeadline,
		descriptorUploadSafety,
		budget,
		strconv.QuoteToASCII(uploadReason),
	)

	uploadCtx, cancel := context.WithTimeout(pkiCtx, budget)
	defer cancel()

	// Generate the non-key parts of the descriptor.
	linkblob, err := p.server.linkKey.Public().MarshalBinary()
	if err != nil {
		return err
	}

	idkeyblob, err := p.server.identityPublicKey.MarshalBinary()
	if err != nil {
		return err
	}

	// Handle the replica NIKE keys.
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

	if err := cpki.IsReplicaDescriptorWellFormed(desc, doPublishEpoch); err != nil {
		p.GetLogger().Noticef(
			"REPLICA DESCRIPTOR UPLOAD: refusing to send malformed replica descriptor %s for epoch %d: %s",
			strconv.QuoteToASCII(desc.Name),
			doPublishEpoch,
			strconv.QuoteToASCII(err.Error()),
		)
		return fmt.Errorf("refusing to send malformed replica descriptor for epoch %d: %w", doPublishEpoch, err)
	}

	p.GetLogger().Noticef(
		"REPLICA DESCRIPTOR UPLOAD: attempting to upload replica descriptor %s for epoch %d",
		strconv.QuoteToASCII(desc.Name),
		doPublishEpoch,
	)

	err = p.impl.PostReplica(uploadCtx, doPublishEpoch, p.server.identityPrivateKey, p.server.identityPublicKey, desc)
	switch {
	case err == nil:
		acceptedBy := postReplicaAcceptedAuthorities(p.impl, doPublishEpoch)
		if len(acceptedBy) > 0 {
			quotedAcceptedBy := make([]string, 0, len(acceptedBy))
			for _, authority := range acceptedBy {
				quotedAcceptedBy = append(quotedAcceptedBy, strconv.QuoteToASCII(authority))
			}

			p.GetLogger().Noticef(
				"REPLICA DESCRIPTOR UPLOAD: successfully posted replica descriptor %s for epoch %d accepted_by=%v",
				strconv.QuoteToASCII(desc.Name),
				doPublishEpoch,
				quotedAcceptedBy,
			)
		} else {
			p.GetLogger().Noticef(
				"REPLICA DESCRIPTOR UPLOAD: successfully posted replica descriptor %s for epoch %d accepted_by=unknown",
				strconv.QuoteToASCII(desc.Name),
				doPublishEpoch,
			)
		}
		p.lastPublishedEpoch = doPublishEpoch
		return nil

	case errors.Is(err, cpki.ErrInvalidPostEpoch):
		p.GetLogger().Warningf(
			"REPLICA DESCRIPTOR UPLOAD: authority permanently rejected replica descriptor %s upload for epoch %d; advancing past this epoch: %s",
			strconv.QuoteToASCII(desc.Name),
			doPublishEpoch,
			strconv.QuoteToASCII(err.Error()),
		)
		if doPublishEpoch > p.lastPublishedEpoch {
			p.lastPublishedEpoch = doPublishEpoch
		}
		return err

	default:
		p.GetLogger().Warningf(
			"REPLICA DESCRIPTOR UPLOAD: failed to upload replica descriptor %s for epoch %d; PKI document fetch will continue: %s",
			strconv.QuoteToASCII(desc.Name),
			doPublishEpoch,
			strconv.QuoteToASCII(err.Error()),
		)
		return err
	}
}

// SPDX-FileCopyrightText: © 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"context"
	"crypto/hmac"
	"errors"
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
	replicaCommon "github.com/katzenpost/katzenpost/replica/common"
)

const NumPKIDocsToFetch = 3

var (
	PublishDeadline     = vServer.PublishConsensusDeadline
	mixServerCacheDelay = epochtime.Period / 16
	nextFetchTill       = epochtime.Period - (PublishDeadline + mixServerCacheDelay)
	recheckInterval     = epochtime.Period / 32
)

type PKIWorker struct {
	worker.Worker

	server *Server
	*pki.WorkerBase

	replicas *replicaCommon.ReplicaMap

	impl pki.Client // PKI client for document fetching and publishing

	lastPublishedEpoch        uint64
	lastWarnedEpoch           uint64
	lastPublishedReplicaEpoch uint64
}

func newPKIWorker(server *Server, pkiClient pki.Client, log *logging.Logger) (*PKIWorker, error) {
	p := &PKIWorker{
		server:     server,
		WorkerBase: pki.NewWorkerBase(pkiClient, log),
		replicas:   replicaCommon.NewReplicaMap(),
		impl:       pkiClient,
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
		// Convert milliseconds to seconds for PKI client timeouts
		DialTimeoutSec:      server.cfg.ConnectTimeout / 1000,
		HandshakeTimeoutSec: server.cfg.HandshakeTimeout / 1000,
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

// HasCurrentPKIDocument returns true if the courier has a PKI document for the current epoch.
// This is useful for integration tests to check if the courier is ready.
func (p *PKIWorker) HasCurrentPKIDocument() bool {
	epoch, _, _ := epochtime.Now()
	return p.EntryForEpoch(epoch) != nil
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
	p.ClearFailedFetch(epoch)

	p.GetLogger().Debugf("Force fetching PKI document for epoch %v", epoch)

	// Fetch the PKI document directly from the client (like replica does)
	ctx := context.Background()
	d, rawDoc, err := p.impl.GetPKIDocumentForEpoch(ctx, epoch)
	if err != nil {
		p.GetLogger().Warningf("Force fetch failed for epoch %v: %v", epoch, err)
		return err
	}

	// Store the document and update replicas
	p.StoreDocument(epoch, d, rawDoc)
	p.replicas.UpdateFromPKIDoc(d)

	p.GetLogger().Debugf("Successfully force fetched PKI document for epoch %v", epoch)
	return nil
}

func (p *PKIWorker) worker() {
	var initialSpawnDelay = epochtime.Period / 64
	timer := time.NewTimer(initialSpawnDelay)
	defer timer.Stop()

	pkiCtx, cancelFn, isCanceled := pki.SetupWorkerContext(p.HaltCh(), p.WorkerBase.GetLogger())
	defer cancelFn()

	var lastUpdateEpoch uint64

	for {
		if !pki.HandleTimerEvent(timer, pkiCtx, p.HaltCh(), p.WorkerBase.GetLogger()) {
			return
		}

		didUpdate := p.fetchDocuments(pkiCtx, isCanceled)
		p.processDocuments(didUpdate)
		p.updateCurrentEpoch(&lastUpdateEpoch)
		p.UpdateTimer(timer)
	}
}

// fetchDocuments fetches PKI documents for required epochs
func (p *PKIWorker) fetchDocuments(pkiCtx context.Context, isCanceled func() bool) bool {
	// If we don't have a current PKI document, be more aggressive about retrying
	currentEpoch, _, _ := epochtime.Now()
	if p.EntryForEpoch(currentEpoch) == nil {
		p.GetLogger().Debugf("No current PKI document for epoch %v, clearing failed fetches to force retry", currentEpoch)
		p.ClearFailedFetch(currentEpoch)
		// Also clear failed fetches for recent epochs to allow retries
		for i := uint64(0); i < 3; i++ {
			if currentEpoch >= i {
				p.ClearFailedFetch(currentEpoch - i)
			}
		}
	}

	results := p.FetchDocuments(pkiCtx, isCanceled)
	if len(results) == 0 {
		return false
	}

	var didUpdate bool
	for _, result := range results {
		if result.Skipped || result.Error != nil {
			continue
		}

		p.StoreDocument(result.Epoch, result.Doc, result.RawDoc)
		didUpdate = true
		p.replicas.UpdateFromPKIDoc(result.Doc)
	}

	return didUpdate
}

// processDocuments handles document cleanup and pruning
func (p *PKIWorker) processDocuments(didUpdate bool) {
	p.PruneFailures()
	if didUpdate {
		// Dispose of the old PKI documents.
		p.PruneDocuments()
	}
}

// updateCurrentEpoch updates components when a new epoch document is available
func (p *PKIWorker) updateCurrentEpoch(lastUpdateEpoch *uint64) {
	// Internal component depend on network wide parameters, and or the
	// list of nodes.  Update if there is a new document for the current
	// epoch.
	if now, _, _ := epochtime.Now(); now > *lastUpdateEpoch {
		if doc := p.EntryForEpoch(now); doc != nil {
			*lastUpdateEpoch = now
		}
	}
}

func (p *PKIWorker) AuthenticateReplicaConnection(c *wire.PeerCredentials) (*pki.ReplicaDescriptor, bool) {
	if len(c.AdditionalData) != sConstants.NodeIDLength {
		p.GetLogger().Debugf("AuthenticateConnection: '%x' AD not an IdentityKey?.", c.AdditionalData)
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
		// TODO could be link key from prev/next epoch too?
		return nil, false
	}
	return replicaDesc, true
}

// SetDocumentForEpoch sets a PKI document for a specific epoch; for testing only.
func (p *PKIWorker) SetDocumentForEpoch(epoch uint64, doc *pki.Document, rawDoc []byte) {
	p.WorkerBase.SetDocumentForEpoch(epoch, doc, rawDoc)
	p.replicas.UpdateFromPKIDoc(doc)
}

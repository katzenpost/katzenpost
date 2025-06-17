// SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package replica

import (
	"context"
	"crypto/hmac"
	"errors"
	"net/url"
	"time"

	"golang.org/x/crypto/blake2b"
	"gopkg.in/op/go-logging.v1"

	"github.com/katzenpost/hpqc/kem/schemes"

	vClient "github.com/katzenpost/katzenpost/authority/voting/client"
	vServer "github.com/katzenpost/katzenpost/authority/voting/server"
	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/worker"
	replicaCommon "github.com/katzenpost/katzenpost/replica/common"
)

const PKIDocNum = 3

var (
	PublishDeadline     = vServer.PublishConsensusDeadline
	mixServerCacheDelay = epochtime.Period / 16
	nextFetchTill       = epochtime.Period - (PublishDeadline + mixServerCacheDelay)
	client2FetchDelay   = 2 * time.Minute
	recheckInterval     = epochtime.Period / 16
)

type PKIWorker struct {
	worker.Worker

	server *Server
	*pki.WorkerBase

	replicas *replicaCommon.ReplicaMap

	impl pki.Client // PKI client for document fetching and publishing

	descAddrMap               map[string][]string
	lastPublishedEpoch        uint64
	lastWarnedEpoch           uint64
	lastPublishedReplicaEpoch uint64
}

// newPKIWorker creates a PKIWorker with the default voting client
func newPKIWorker(server *Server, log *logging.Logger) (*PKIWorker, error) {
	kemscheme := schemes.ByName(server.cfg.WireKEMScheme)
	if kemscheme == nil {
		return nil, errors.New("kem scheme not found in registry")
	}
	pkiCfg := &vClient.Config{
		KEMScheme:   kemscheme,
		LinkKey:     server.linkKey,
		LogBackend:  server.LogBackend(),
		Authorities: server.cfg.PKI.Voting.Authorities,
		Geo:         server.cfg.SphinxGeometry,
	}

	pkiClient, err := vClient.New(pkiCfg)
	if err != nil {
		return nil, err
	}

	return newPKIWorkerWithClient(server, pkiClient, log)
}

// newPKIWorkerWithClient creates a PKIWorker with a custom pki.Client for testing
func newPKIWorkerWithClient(server *Server, pkiClient pki.Client, log *logging.Logger) (*PKIWorker, error) {
	p := &PKIWorker{
		server:      server,
		WorkerBase:  pki.NewWorkerBase(pkiClient, log),
		replicas:    replicaCommon.NewReplicaMap(),
		descAddrMap: make(map[string][]string),
		impl:        pkiClient,
	}

	for _, v := range server.cfg.Addresses {
		u, err := url.Parse(v)
		if err != nil {
			return nil, err
		}
		if _, ok := p.descAddrMap[u.Scheme]; ok {
			p.descAddrMap[u.Scheme] = append(p.descAddrMap[u.Scheme], v)
		} else {
			p.descAddrMap[u.Scheme] = []string{v}
		}
	}

	p.Go(p.worker)

	return p, nil
}

func replicaMap(doc *pki.Document) map[[32]byte]*pki.ReplicaDescriptor {
	newReplicas := make(map[[32]byte]*pki.ReplicaDescriptor)
	for _, replica := range doc.StorageReplicas {
		replicaIdHash := blake2b.Sum256(replica.IdentityKey)
		newReplicas[replicaIdHash] = replica
	}
	return newReplicas
}

// isSubset returns true is a is a subset of b
func isSubset(a, b map[[32]byte]*pki.ReplicaDescriptor) bool {
	for key, _ := range a {
		_, ok := b[key]
		if !ok {
			return false
		}
	}
	return true
}

func equal(a, b map[[32]byte]*pki.ReplicaDescriptor) bool {
	for key, _ := range a {
		_, ok := b[key]
		if !ok {
			return false
		}
	}
	for key, _ := range b {
		_, ok := a[key]
		if !ok {
			return false
		}
	}
	return true
}

func (p *PKIWorker) updateReplicas(doc *pki.Document) {
	newReplicas := replicaMap(doc)
	switch {
	case equal(p.replicas.Copy(), newReplicas):
		// no op
	case !isSubset(p.replicas.Copy(), newReplicas):
		// removing replica(s)
		fallthrough
	case !isSubset(newReplicas, p.replicas.Copy()):
		// adding replica(s)
		p.replicas.Replace(newReplicas)
		err := p.server.state.Rebalance()
		if err != nil {
			p.GetLogger().Errorf("Rebalance failure: %s", err)
		}
	}
}

// ReplicasCopy returns a copy of the replicas map
func (p *PKIWorker) ReplicasCopy() map[[32]byte]*pki.ReplicaDescriptor {
	return p.replicas.Copy()
}

// Keep the documentForEpoch method public so it can be used by IsPeerValid
func (p *PKIWorker) documentForEpoch(epoch uint64) *pki.Document {
	return p.EntryForEpoch(epoch)
}

// ForceFetchPKI forces the PKI worker to fetch a new PKI document for the current epoch.
// This is useful for integration tests where you want to ensure the replica has the latest
// PKI document without waiting for the normal fetch cycle.
func (p *PKIWorker) ForceFetchPKI() error {
	if p.impl == nil {
		return errors.New("no PKI client configured")
	}

	epoch, _, _ := epochtime.Now()

	// Clear any failed fetch record for this epoch to allow retry
	p.ClearFailedFetch(epoch)

	p.GetLogger().Debugf("Force fetching PKI document for epoch %v", epoch)

	// Fetch the PKI document
	ctx := context.Background()
	d, rawDoc, err := p.impl.Get(ctx, epoch)
	if err != nil {
		p.GetLogger().Warningf("Force fetch failed for epoch %v: %v", epoch, err)
		return err
	}

	// Validate sphinx geometry
	if !hmac.Equal(d.SphinxGeometryHash, p.server.cfg.SphinxGeometry.Hash()) {
		return errors.New("sphinx geometry mismatch")
	}

	// Update replicas and store the document
	p.updateReplicas(d)
	p.StoreDocument(epoch, d, rawDoc)

	p.GetLogger().Debugf("Successfully force fetched PKI document for epoch %v", epoch)

	// Kick the connector to update connections
	p.server.connector.ForceUpdate()

	return nil
}

// HasCurrentPKIDocument returns true if the replica has a PKI document for the current epoch.
// This is useful for integration tests to check if the replica is ready.
func (p *PKIWorker) HasCurrentPKIDocument() bool {
	epoch, _, _ := epochtime.Now()
	return p.documentForEpoch(epoch) != nil
}

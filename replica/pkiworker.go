// SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package replica

import (
	"context"
	"crypto/hmac"
	"errors"
	"sync"
	"time"

	"golang.org/x/crypto/blake2b"
	"gopkg.in/op/go-logging.v1"

	"github.com/katzenpost/hpqc/kem/schemes"

	vClient "github.com/katzenpost/katzenpost/authority/voting/client"
	vServer "github.com/katzenpost/katzenpost/authority/voting/server"
	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/pki"
	sConstants "github.com/katzenpost/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/katzenpost/core/wire"
	"github.com/katzenpost/katzenpost/core/worker"
)

const PKIDocNum = 3

var (
	PublishDeadline     = vServer.PublishConsensusDeadline
	mixServerCacheDelay = epochtime.Period / 16
	nextFetchTill       = epochtime.Period - (PublishDeadline + mixServerCacheDelay)
	client2FetchDelay   = 2 * time.Minute
	recheckInterval     = epochtime.Period / 16
)

type ReplicaMap struct {
	sync.RWMutex
	replicas map[[32]byte]*pki.ReplicaDescriptor
}

func newReplicaMap() *ReplicaMap {
	return &ReplicaMap{
		replicas: make(map[[32]byte]*pki.ReplicaDescriptor),
	}
}

func (r *ReplicaMap) GetReplicaDescriptor(nodeID *[32]byte) (*pki.ReplicaDescriptor, bool) {
	r.RLock()
	ret, ok := r.replicas[*nodeID]
	r.RUnlock()
	// NOTE(david): make copy of pki.ReplicaDescriptor? it might be needed, later to avoid
	// data races if one threat mutates the descriptor.
	return ret, ok
}

func (r *ReplicaMap) Replace(newMap map[[32]byte]*pki.ReplicaDescriptor) {
	r.Lock()
	r.replicas = newMap
	r.Unlock()
}

func (r *ReplicaMap) Copy() map[[32]byte]*pki.ReplicaDescriptor {
	ret := make(map[[32]byte]*pki.ReplicaDescriptor)
	r.RLock()
	for k, v := range r.replicas {
		ret[k] = v
	}
	r.RUnlock()
	return ret
}

/*
type Documents struct {
	sync.RWMutex
	docs map[uint64]*pki.Document
}

func newDocuments() *Documents {
	return &Documents{
		docs: make(map[uint64]*pki.Document),
	}
}

func (d *Documents) HasEpoch(epoch uint64) bool {
	d.RLock()
	_, ok := d.docs[epoch]
	d.RUnlock()
	return ok
}

func (d *Documents) SetEpoch(epoch uint64, doc *pki.Document) {
	d.Lock()
	d.docs[epoch] = doc
	d.Unlock()
}

func (d *Documents) Replace(newDoc map[uint64]*pki.Document) {
	d.Lock()
	d.docs = newDoc
	d.Unlock()
}

func (d *Documents) DocumentsToFetch() []uint64 {
	ret := make([]uint64, 0, PKIDocNum)
	now, _, till := epochtime.Now()
	start := now
	if till < nextFetchTill {
		start = now + 1
	}
	d.RLock()
	defer d.RUnlock()
	for epoch := start; epoch > now-PKIDocNum; epoch-- {
		if _, ok := d.docs[epoch]; !ok {
			ret = append(ret, epoch)
		}
	}
	return ret
}
*/

type PKIWorker struct {
	worker.Worker

	server *Server
	log    *logging.Logger

	replicas *ReplicaMap

	impl pki.Client

	lock               *sync.RWMutex
	descAddrMap        map[string][]string
	docs               map[uint64]*pki.Document
	rawDocs            map[uint64][]byte
	failedFetches      map[uint64]error
	lastPublishedEpoch uint64
	lastWarnedEpoch    uint64
}

func newPKIWorker(server *Server, log *logging.Logger) (*PKIWorker, error) {
	p := &PKIWorker{
		server:        server,
		log:           log,
		replicas:      newReplicaMap(),
		lock:          new(sync.RWMutex),
		docs:          make(map[uint64]*pki.Document),
		rawDocs:       make(map[uint64][]byte),
		failedFetches: make(map[uint64]error),
	}

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

	var err error
	p.impl, err = vClient.New(pkiCfg)
	if err != nil {
		return nil, err
	}

	// XXX we should get rid of our use of the thin client
	// and instead rely on the dirauth client: p.impl
	doc := p.server.thinClient.PKIDocument()

	// XXX we can do this later...
	p.replicas.Replace(replicaMap(doc))

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

// returns the set of elements in A but not in B
func difference(a, b map[[32]byte]*pki.ReplicaDescriptor) map[[32]byte]*pki.ReplicaDescriptor {
	out := make(map[[32]byte]*pki.ReplicaDescriptor)
	for key, v := range a {
		_, ok := b[key]
		if !ok {
			out[key] = v
		}
	}
	return out
}

func equal(a, b map[[32]byte]*pki.ReplicaDescriptor) bool {
	if len(difference(a, b)) != 0 {
		return false
	}
	if len(difference(b, a)) != 0 {
		return false
	}
	return true
}

/*
func (p *PKIWorker) worker() {
	var till time.Duration
	timer := time.NewTimer(till)

	defer func() {
		p.log.Debug("Halting PKI worker.")
		timer.Stop()
	}()

	for {
		timerFired := false
		select {
		case <-p.HaltCh():
			p.log.Debug("egressWorker shutting down")
			return
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

		doc := p.server.thinClient.PKIDocument()
		newReplicas := replicaMap(doc)
		switch {
		case equal(p.replicas.Copy(), newReplicas):
			// no op
		case len(difference(p.replicas.Copy(), newReplicas)) > 0:
			// removing replica(s)
			fallthrough
		case len(difference(newReplicas, p.replicas.Copy())) > 0:
			// adding replica(s)
			p.replicas.Replace(newReplicas)
			p.server.state.Rebalance()
		}

		timer.Reset(recheckInterval)
	}
}
*/

func (p *PKIWorker) updateReplicas(doc *pki.Document) {
	newReplicas := replicaMap(doc)
	switch {
	case equal(p.replicas.Copy(), newReplicas):
		// no op
	case len(difference(p.replicas.Copy(), newReplicas)) > 0:
		// removing replica(s)
		fallthrough
	case len(difference(newReplicas, p.replicas.Copy())) > 0:
		// adding replica(s)
		p.replicas.Replace(newReplicas)
		p.server.state.Rebalance()
	}
}

func (p *PKIWorker) AuthenticateCourierConnection(c *wire.PeerCredentials) bool {
	if len(c.AdditionalData) != sConstants.NodeIDLength {
		p.log.Debugf("AuthenticateConnection: '%x' AD not an IdentityKey?.", c.AdditionalData)
		return false
	}
	var nodeID [sConstants.NodeIDLength]byte
	copy(nodeID[:], c.AdditionalData)
	doc := p.server.thinClient.PKIDocument()
	serviceDesc, err := doc.GetServiceNodeByKeyHash(&nodeID)
	if err != nil {
		return false
	}
	blob, err := c.PublicKey.MarshalBinary()
	if err != nil {
		panic(err)
	}
	// XXX TODO(david): perhaps check that it has a courier service
	if !hmac.Equal(serviceDesc.LinkKey, blob) {
		return false
	}
	return true
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

func (p *PKIWorker) publishDescriptorIfNeeded(ctx context.Context) error {
	return nil // XXX FIX ME
}

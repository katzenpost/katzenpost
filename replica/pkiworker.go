// SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package replica

import (
	"crypto/hmac"
	"errors"
	"net/url"
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

type PKIWorker struct {
	worker.Worker

	server *Server
	log    *logging.Logger

	replicas *ReplicaMap

	impl pki.Client

	lock                      *sync.RWMutex
	descAddrMap               map[string][]string
	docs                      map[uint64]*pki.Document
	rawDocs                   map[uint64][]byte
	failedFetches             map[uint64]error
	lastPublishedEpoch        uint64
	lastWarnedEpoch           uint64
	lastPublishedReplicaEpoch uint64
}

func newPKIWorker(server *Server, log *logging.Logger) (*PKIWorker, error) {
	p := &PKIWorker{
		server:        server,
		log:           log,
		replicas:      newReplicaMap(),
		lock:          new(sync.RWMutex),
		descAddrMap:   make(map[string][]string),
		docs:          make(map[uint64]*pki.Document),
		rawDocs:       make(map[uint64][]byte),
		failedFetches: make(map[uint64]error),
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
			p.log.Errorf("Rebalance failure: %s", err)
		}
	}
}

func (p *PKIWorker) AuthenticateCourierConnection(c *wire.PeerCredentials) bool {
	if len(c.AdditionalData) != sConstants.NodeIDLength {
		p.log.Debugf("AuthenticateConnection: '%x' AD not an IdentityKey?.", c.AdditionalData)
		return false
	}
	var nodeID [sConstants.NodeIDLength]byte
	copy(nodeID[:], c.AdditionalData)

	epoch, _, _ := epochtime.Now()
	doc := p.entryForEpoch(epoch)
	if doc == nil {
		p.log.Error("PKI doc is nil")
		return false
	}

	serviceDesc, err := doc.GetServiceNodeByKeyHash(&nodeID)
	if err != nil {
		p.log.Error("courier service not found")
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
		p.log.Debug("wtf1")
		return nil, false
	}
	blob, err := c.PublicKey.MarshalBinary()
	if err != nil {
		panic(err)
	}
	if !hmac.Equal(replicaDesc.LinkKey, blob) {
		p.log.Debug("wtf2")
		return nil, false
	}
	return replicaDesc, true
}

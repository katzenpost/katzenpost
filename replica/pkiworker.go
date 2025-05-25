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

	"github.com/katzenpost/hpqc/kem/pem"
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
	log    *logging.Logger

	replicas *common.ReplicaMap

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
		replicas:      common.NewReplicaMap(),
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
	p.log.Debug("---- START AuthenticateCourierConnection")
	const keyEndpoint = "endpoint"

	if len(c.AdditionalData) != 0 {
		p.log.Debugf("AuthenticateConnection: '%x' AD should be zero bytes.", c.AdditionalData)
		return false
	}

	epoch, _, _ := epochtime.Now()

	// Try current epoch first
	doc := p.entryForEpoch(epoch)
	if doc == nil {
		p.log.Debugf("No PKI doc for current epoch %d, trying next epoch", epoch)
		// Try next epoch
		doc = p.entryForEpoch(epoch + 1)
		if doc == nil {
			p.log.Debugf("No PKI doc for next epoch %d, trying previous epoch", epoch+1)
			// Try previous epoch
			doc = p.entryForEpoch(epoch - 1)
			if doc == nil {
				p.log.Errorf("No PKI docs available for epochs %d, %d, or %d", epoch-1, epoch, epoch+1)
				return false
			}
			p.log.Debugf("Using PKI doc from previous epoch %d", epoch-1)
		} else {
			p.log.Debugf("Using PKI doc from next epoch %d", epoch+1)
		}
	} else {
		p.log.Debugf("Using PKI doc from current epoch %d", epoch)
	}

	isCourier := false
	for _, desc := range doc.ServiceNodes {
		if desc.Kaetzchen == nil {
			continue
		}
		rawLinkPubKey, err := desc.GetRawCourierLinkKey()
		if err != nil {
			p.log.Errorf("desc.GetRawCourierLinkKey() failure: %s", err)
			return false
		}
		linkScheme := schemes.ByName(p.server.cfg.WireKEMScheme)
		linkPubKey, err := pem.FromPublicPEMString(rawLinkPubKey, linkScheme)
		if err != nil {
			p.log.Errorf("AuthenticateCourierConnection failed to unmarshal courier link key: %s", err)
		}
		if c.PublicKey.Equal(linkPubKey) {
			isCourier = true
		}
	}
	p.log.Debug("---- END AuthenticateCourierConnection")
	return isCourier
}

func (p *PKIWorker) AuthenticateReplicaConnection(c *wire.PeerCredentials) (*pki.ReplicaDescriptor, bool) {
	p.log.Debug("---- START AuthenticateReplicaConnection")
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

	p.log.Debug("---- END AuthenticateReplicaConnection")
	return replicaDesc, true
}

// SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package replica

import (
	"crypto/hmac"
	"time"

	"golang.org/x/crypto/blake2b"
	"gopkg.in/op/go-logging.v1"

	vServer "github.com/katzenpost/katzenpost/authority/voting/server"
	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/pki"
	sConstants "github.com/katzenpost/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/katzenpost/core/wire"
	"github.com/katzenpost/katzenpost/core/worker"
)

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

	replicas     map[[32]byte]*pki.ReplicaDescriptor
	currentEpoch uint64
}

func newPKIWorker(server *Server, log *logging.Logger) *PKIWorker {
	p := &PKIWorker{
		server:   server,
		log:      log,
		replicas: make(map[[32]byte]*pki.ReplicaDescriptor),
	}
	doc := p.server.thinClient.PKIDocument()
	p.replicas = replicaMap(doc)
	p.currentEpoch = doc.Epoch
	return p
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

func (p *PKIWorker) worker() {
	var till time.Duration
	p.currentEpoch, _, till = epochtime.Now()
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
		case equal(p.replicas, newReplicas):
			// no op
		case len(difference(p.replicas, newReplicas)) > 0:
			// removing replica(s)
			fallthrough
		case len(difference(newReplicas, p.replicas)) > 0:
			// adding replica(s)
			p.replicas = newReplicas
			p.server.state.Rebalance()
		}

		timer.Reset(recheckInterval)
	}
}

func (p *PKIWorker) AuthenticateConnection(c *wire.PeerCredentials) bool {
	if len(c.AdditionalData) != sConstants.NodeIDLength {
		p.log.Debugf("AuthenticateConnection: '%x' AD not an IdentityKey?.", c.AdditionalData)
		return false
	}
	var nodeID [sConstants.NodeIDLength]byte
	copy(nodeID[:], c.AdditionalData)

	replicaDesc, isReplica := p.replicas[nodeID]
	var isCourier bool
	doc := p.server.thinClient.PKIDocument()
	serviceDesc, err := doc.GetServiceNodeByKeyHash(&nodeID)
	if err != nil {
		isCourier = true
	}

	blob, err := c.PublicKey.MarshalBinary()
	if err != nil {
		panic(err)
	}

	switch {
	case isReplica:
		if !hmac.Equal(replicaDesc.LinkKey, blob) {
			return false
		}
	case isCourier:
		// TODO(david): perhaps check that it has a courier service
		if !hmac.Equal(serviceDesc.LinkKey, blob) {
			return false
		}
	}
	return true
}

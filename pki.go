// pki.go - Katzenpost server PKI interface.
// Copyright (C) 2017  Yawning Angel.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

package server

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	nClient "github.com/katzenpost/authority/nonvoting/client"
	"github.com/katzenpost/core/crypto/ecdh"
	"github.com/katzenpost/core/crypto/eddsa"
	"github.com/katzenpost/core/epochtime"
	cpki "github.com/katzenpost/core/pki"
	"github.com/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/core/wire"
	"github.com/katzenpost/core/worker"
	"github.com/katzenpost/server/internal/pkicache"
	"gopkg.in/op/go-logging.v1"
)

var errNotCached = errors.New("pki: requested epoch document not in cache")

type pki struct {
	sync.RWMutex
	worker.Worker

	s    *Server
	log  *logging.Logger
	impl cpki.Client

	docs               map[uint64]*pkicache.Entry
	rawDocs            map[uint64][]byte
	failedFetches      map[uint64]error
	lastPublishedEpoch uint64
	lastWarnedEpoch    uint64
}

func (p *pki) startWorker() {
	p.Go(p.worker)
}

func (p *pki) worker() {
	const initialSpawnDelay = 5 * time.Second

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

	for {
		const recheckInterval = 1 * time.Minute

		timerFired := false
		select {
		case <-p.HaltCh():
			p.log.Debugf("Terminating gracefully.")
			return
		case <-pkiCtx.Done():
			return
		case <-timer.C:
			timerFired = true
		}
		if !timerFired && !timer.Stop() {
			<-timer.C
		}

		// Fetch the PKI documents as required.
		didUpdate := false
		for _, epoch := range p.documentsToFetch() {
			// Certain errors in fetching documents are treated as hard
			// failures that suppress further attempts to fetch the document
			// for the epoch.
			if err, ok := p.getFailedFetch(epoch); ok {
				p.log.Debugf("Skipping fetch for epoch %v: %v", epoch, err)
				continue
			}

			d, rawDoc, err := p.impl.Get(pkiCtx, epoch)
			if isCanceled() {
				// Canceled mid-fetch.
				return
			}
			if err != nil {
				p.log.Warningf("Failed to fetch PKI for epoch %v: %v", epoch, err)
				if err == cpki.ErrNoDocument {
					p.setFailedFetch(epoch, err)
				}
				continue
			}

			ent, err := pkicache.New(d, p.s.identityKey.PublicKey(), p.s.cfg.Server.IsProvider)
			if err != nil {
				p.log.Warningf("Failed to generate PKI cache for epoch %v: %v", epoch, err)
				p.setFailedFetch(epoch, err)
				continue
			}
			if err = p.validateCacheEntry(ent); err != nil {
				p.log.Warningf("Generated PKI cache is invalid: %v", err)
				p.setFailedFetch(epoch, err)
				continue
			}

			p.Lock()
			p.rawDocs[epoch] = rawDoc
			p.docs[epoch] = ent
			p.Unlock()
			didUpdate = true
		}
		p.pruneFailures()
		if didUpdate {
			// Dispose of the old PKI documents.
			p.pruneDocuments()

			// If the PKI document map changed, kick the connector worker.
			p.s.connector.forceUpdate()
		}

		// Check to see if we need to publish the descriptor, and do so, along
		// with all the key rotation bits.
		err := p.publishDescriptorIfNeeded(pkiCtx)
		if isCanceled() {
			// Canceled mid-post
			return
		}
		if err != nil {
			p.log.Warningf("Failed to post to PKI: %v", err)
		}

		timer.Reset(recheckInterval)
	}
}

func (p *pki) validateCacheEntry(ent *pkicache.Entry) error {
	// This just does light-weight validation on self, primarily to catch
	// dumb bugs.  Anything more is somewhat silly because authorities are
	// a trust root, and no amount of checking here will save us if the
	// authorities are malicious.
	desc := ent.Self()
	if desc.Name != p.s.cfg.Server.Identifier {
		return fmt.Errorf("self Name field does not match Identifier")
	}
	if !desc.IdentityKey.Equal(p.s.identityKey.PublicKey()) {
		return fmt.Errorf("self identity key mismatch")
	}
	if !desc.LinkKey.Equal(p.s.linkKey.PublicKey()) {
		return fmt.Errorf("self link key mismatch")
	}
	return nil
}

func (p *pki) getFailedFetch(epoch uint64) (error, bool) {
	p.RLock()
	defer p.RUnlock()
	err, ok := p.failedFetches[epoch]
	return err, ok
}

func (p *pki) setFailedFetch(epoch uint64, err error) {
	p.Lock()
	defer p.Unlock()
	p.failedFetches[epoch] = err
}

func (p *pki) pruneFailures() {
	p.Lock()
	defer p.Unlock()

	now, _, _ := epochtime.Now()

	for epoch := range p.failedFetches {
		// Be more aggressive about pruning failures than pruning documents,
		// the worst that can happen is that we query the PKI unneccecarily.
		if epoch < now-(numMixKeys-1) || epoch > now+1 {
			delete(p.failedFetches, epoch)
		}
	}
}

func (p *pki) pruneDocuments() {
	now, _, _ := epochtime.Now()

	p.Lock()
	defer p.Unlock()
	for epoch := range p.docs {
		if epoch < now-(numMixKeys-1) {
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

func (p *pki) publishDescriptorIfNeeded(pkiCtx context.Context) error {
	const publishDeadline = 3600 * time.Second

	epoch, _, till := epochtime.Now()
	doPublishEpoch := uint64(0)
	switch p.lastPublishedEpoch {
	case 0:
		// Initial startup.  Regardless of the deadline, publish.
		p.log.Debugf("Initial startup or correcting for time jump.")
		doPublishEpoch = epoch
	case epoch:
		// Check the deadline for the next publication time.
		if till > publishDeadline {
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
	addrMap, err := makeDescAddrMap(p.s.cfg.Server.Addresses)
	if err != nil {
		return err
	}
	desc := &cpki.MixDescriptor{
		Name:        p.s.cfg.Server.Identifier,
		IdentityKey: p.s.identityKey.PublicKey(),
		LinkKey:     p.s.linkKey.PublicKey(),
		Addresses:   addrMap,
	}
	if p.s.cfg.Server.IsProvider {
		// Only set the layer if the node is a provider.  Otherwise, nodes
		// shouldn't be self assigning this.
		desc.Layer = cpki.LayerProvider
	}
	desc.MixKeys = make(map[uint64]*ecdh.PublicKey)

	// Ensure that there are mix keys for the epochs [e, ..., e+2],
	// assuming that key rotation isn't disabled, and fill them into
	// the descriptor.
	if didGen, err := p.s.mixKeys.generateMixKeys(doPublishEpoch); err == nil {
		// Prune off the old mix keys.  Bad things happen if the epoch ever
		// goes backwards, but everyone uses NTP right?
		didPrune := p.s.mixKeys.pruneMixKeys()

		// Add the keys to the descriptor.
		for e := doPublishEpoch; e < doPublishEpoch+numMixKeys; e++ {
			// Why, yes, this doesn't hold the lock.  The only time the map is
			// altered is in mixkeys.generateMixKeys(), and mixkeys.pruneMixKeys(),
			// both of which are only called from this code path serially.
			k, ok := p.s.mixKeys.keys[e]
			if !ok {
				// The prune pass must have purged a key we intended to publish,
				// so bail out and try again in a little while.
				return fmt.Errorf("key that was scheduled for publication got pruned")
			}
			desc.MixKeys[e] = k.PublicKey()
		}
		if didGen || didPrune {
			// Kick the crypto workers into reshadowing the mix keys,
			// since there are either new keys, or less old keys.
			p.s.reshadowCryptoWorkers()
		}
	} else {
		// Sad panda, failed to generate the keys.
		return err
	}

	// Post the descriptor to all the authorities.
	err = p.impl.Post(pkiCtx, doPublishEpoch, p.s.identityKey, desc)
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
	}

	return err
}

func (p *pki) documentsToFetch() []uint64 {
	const nextFetchTill = 45 * time.Minute

	ret := make([]uint64, 0, numMixKeys+1)
	now, _, till := epochtime.Now()
	start := now
	if till < nextFetchTill {
		start = now + 1
	}

	p.RLock()
	defer p.RUnlock()

	for epoch := start; epoch > now-numMixKeys; epoch-- {
		if _, ok := p.docs[epoch]; !ok {
			ret = append(ret, epoch)
		}
	}

	return ret
}

func (p *pki) documentsForAuthentication() ([]*pkicache.Entry, *pkicache.Entry, uint64, time.Duration) {
	const pkiEarlyConnectSlack = 30 * time.Minute

	// Figure out the list of epochs to consider valid.
	//
	// Note: The ordering is important and should not be changed without
	// changes to pki.authenticateConnection().
	now, _, till := epochtime.Now()
	epochs := make([]uint64, 0, numMixKeys+1)
	start := now
	if till < pkiEarlyConnectSlack {
		// Allow connections to new nodes 30 mins in advance of an epoch
		// transition.
		start = now + 1
	}
	for epoch := start; epoch > now-numMixKeys; epoch-- {
		epochs = append(epochs, epoch)
	}

	// Return the list of cache entries.
	p.RLock()
	defer p.RUnlock()

	var nowDoc *pkicache.Entry
	s := make([]*pkicache.Entry, 0, len(epochs))
	for _, epoch := range epochs {
		if e, ok := p.docs[epoch]; ok {
			s = append(s, e)
			if epoch == now {
				nowDoc = e
			}
		}
	}
	return s, nowDoc, now, till
}

func (p *pki) authenticateConnection(c *wire.PeerCredentials, isOutgoing bool) (desc *cpki.MixDescriptor, canSend, isValid bool) {
	const earlySendSlack = 2 * time.Minute

	dirStr := "Incoming"
	if isOutgoing {
		dirStr = "Outgoing"
	}

	// Ensure the additional data is valid.
	if len(c.AdditionalData) != constants.NodeIDLength {
		p.log.Debugf("%v: '%v' AD not an IdentityKey?.", dirStr, bytesToPrintString(c.AdditionalData))
		return nil, false, false
	}
	var nodeID [constants.NodeIDLength]byte
	copy(nodeID[:], c.AdditionalData)

	// Iterate over whatever documents we happen to have for the epochs
	// [now+1, now, now-1, now-2].
	docs, nowDoc, now, till := p.documentsForAuthentication()
	for _, d := range docs {
		var m *cpki.MixDescriptor
		switch isOutgoing {
		case true:
			m = d.GetOutgoingByID(&nodeID)
		case false:
			m = d.GetIncomingByID(&nodeID)
		}
		if m == nil {
			continue
		}
		if desc == nil { // This is the most recent descriptor we have.
			desc = m
		}

		// The LinkKey that is being used for authentication should
		// match what is listed in the descriptor in the document, or
		// the most recent descriptor we have for the node.
		if !m.LinkKey.Equal(c.PublicKey) {
			if desc == m || !desc.LinkKey.Equal(c.PublicKey) {
				p.log.Warningf("%v: '%v' Public Key mismatch: '%v'", dirStr, bytesToPrintString(c.AdditionalData), c.PublicKey)
				continue
			}
		}

		switch d.Epoch() {
		case now:
			// The node is listed in the document for the current epoch.
			return desc, true, true
		case now + 1:
			// The node is listed in the document from the next epoch..
			if !isOutgoing && till < earlySendSlack {
				// And this is an incoming connection, and it is less than
				// the slack till the transition.
				//
				// Outgoing connections do not apply the early send slack
				// as only one side needs to apply it to be somewhat clock
				// skew tollerant.
				return desc, true, true
			}
			isValid = true
		default:
			// The node is listed in the document for one of the previous
			// epochs for which there are still valid mix keys...
			if nowDoc == nil {
				// If we do not have a document for the current epoch,
				// we can't check to see if the node has been de-listed
				// or not.
				continue
			}
			if currDesc := nowDoc.GetByID(&nodeID); currDesc != nil {
				// The node listed in the old document exists in the
				// document for the new epoch, so continue to send
				// to it, until the mix keys in the old descriptor
				// expire.
				return desc, true, true
			}
		}
	}

	return
}

func (p *pki) outgoingDestinations() map[[constants.NodeIDLength]byte]*cpki.MixDescriptor {
	docs, nowDoc, now, _ := p.documentsForAuthentication()
	descMap := make(map[[constants.NodeIDLength]byte]*cpki.MixDescriptor)

	for _, d := range docs {
		docEpoch := d.Epoch()

		// If we are attempting to add nodes from the past document, and
		// we do not have the current document, then we can't validate that
		// the node should continue to be honored.
		if docEpoch < now && nowDoc == nil {
			continue
		}

		for _, v := range d.Outgoing() {
			nodeID := v.IdentityKey.ByteArray()

			// Ignore nodes from past epochs that are not listed in the
			// current document.
			if docEpoch < now && nowDoc.GetByID(&nodeID) == nil {
				continue
			}

			// De-duplicate.
			if _, ok := descMap[nodeID]; !ok {
				descMap[nodeID] = v
			}
		}
	}
	return descMap
}

// getConsensus returns a raw byte sliced of the cached consensus document
// specified by epoch. Returns cpki.ErrNoDocument if the epoch is in our
// list of rejected epochs. Returns errNotCached if document not in PKI cache.
func (p *pki) getConsensus(epoch uint64) ([]byte, error) {
	if err, ok := p.getFailedFetch(epoch); ok {
		p.log.Debugf("getConsensus failure: no cached PKI document for epoch %v: %v", epoch, err)
		return nil, cpki.ErrNoDocument
	}
	p.RLock()
	defer p.RUnlock()
	val, ok := p.rawDocs[epoch]
	if !ok {
		now, _, _ := epochtime.Now()
		// Return cpki.ErrNoDocument if documents will never exist.
		if epoch < now-1 {
			return nil, cpki.ErrNoDocument
		}
		return nil, errNotCached
	}
	return val, nil
}

func newPKI(s *Server) (*pki, error) {
	p := new(pki)
	p.s = s
	p.log = s.logBackend.GetLogger("pki")
	p.docs = make(map[uint64]*pkicache.Entry)
	p.rawDocs = make(map[uint64][]byte)
	p.failedFetches = make(map[uint64]error)

	if s.cfg.PKI.Nonvoting != nil {
		authPk := new(eddsa.PublicKey)
		err := authPk.FromString(s.cfg.PKI.Nonvoting.PublicKey)
		if err != nil {
			return nil, fmt.Errorf("BUG: pki: Failed to deserialize validated public key: %v", err)
		}
		pkiCfg := &nClient.Config{
			LogBackend: s.logBackend,
			Address:    s.cfg.PKI.Nonvoting.Address,
			PublicKey:  authPk,
		}
		p.impl, err = nClient.New(pkiCfg)
		if err != nil {
			return nil, err
		}
	}
	// TODO: Wire in a real PKI implementation in addition to the test one.

	// Note: This does not start the worker immediately since the worker can
	// make calls into the connector and crypto workers (on PKI updates),
	// which are initialized after the pki object.

	return p, nil
}

func makeDescAddrMap(addrs []string) (map[cpki.Transport][]string, error) {
	m := make(map[cpki.Transport][]string)
	for _, addr := range addrs {
		h, p, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		if _, err = strconv.ParseUint(p, 10, 16); err != nil {
			return nil, err
		}

		var t cpki.Transport
		ip := net.ParseIP(h)
		if ip == nil {
			return nil, fmt.Errorf("address '%v' is not an IP", h)
		}
		switch {
		case ip.To4() != nil:
			t = cpki.TransportTCPv4
		case ip.To16() != nil:
			t = cpki.TransportTCPv6
		default:
			return nil, fmt.Errorf("address '%v' is neither IPv4 nor IPv6", h)
		}

		m[t] = append(m[t], addr)
	}
	return m, nil
}

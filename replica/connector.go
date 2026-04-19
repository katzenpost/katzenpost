// SPDX-FileCopyrightText: Copyright (C) 2017  Yawning Angel.
// SPDX-License-Identifier: AGPL-3.0-only

package replica

import (
	"crypto/hmac"
	"sync"
	"time"

	"golang.org/x/crypto/blake2b"
	"gopkg.in/op/go-logging.v1"

	"github.com/katzenpost/hpqc/hash"
	"github.com/katzenpost/hpqc/kem/schemes"

	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/katzenpost/core/wire/commands"
	"github.com/katzenpost/katzenpost/core/worker"
	replicaCommon "github.com/katzenpost/katzenpost/replica/common"
	"github.com/katzenpost/katzenpost/replica/instrument"
)

type Connector struct {
	sync.RWMutex
	worker.Worker

	server *Server
	log    *logging.Logger

	conns         map[[constants.NodeIDLength]byte]*outgoingConn
	forceUpdateCh chan interface{}

	replicationSem chan struct{}

	// Retry queue for commands that couldn't be dispatched due to missing connections
	retryQueue   []retryCommand
	retryQueueMu sync.Mutex

	closeAllCh chan interface{}
	closeAllWg sync.WaitGroup
}

// retryCommand holds a command that needs to be retried when connections become available
type retryCommand struct {
	cmd       commands.Command
	idHash    [32]byte
	// ident is a per-cmd fingerprint used for dedup. Zero and hasIdent=false
	// for command types with no natural identity — those are never deduped.
	ident     [32]byte
	hasIdent  bool
	attempts  int
	firstSeen time.Time
	lastTry   time.Time
}

// Retry queue bounds. Exposed as vars (not const) so tests can shrink them.
var (
	// maxRetryQueuePerPeer caps the number of pending retries to a single peer.
	// Prevents one offline peer from crowding out retries destined for others.
	// When exceeded, the oldest entry for that peer is evicted (FIFO).
	maxRetryQueuePerPeer = 2000
	// retryTTL is how long a pending retry may live before it is pruned.
	// Longer outages should be healed by Rebalance, not this queue.
	retryTTL = 3 * epochtime.Period
)

func (co *Connector) Halt() {
	co.Worker.Halt()

	// Close all outgoing connections.
	close(co.closeAllCh)
	co.closeAllWg.Wait()
}

func (co *Connector) ForceUpdate() {
	// This deliberately uses a non-blocking write to a buffered channel so
	// that the resweeps happen reliably.  Since the resweep is comprehensive,
	// there's no benefit to queueing more than one resweep request, and the
	// periodic timer serves as a fallback.
	select {
	case co.forceUpdateCh <- true:
	default:
	}
}

func (co *Connector) Server() *Server {
	return co.server
}

// cmdIdentity returns a 32-byte fingerprint identifying the logical command,
// used as a dedup key in the retry queue. Returns ok=false for command types
// that have no natural identity — those are appended without dedup.
func cmdIdentity(cmd commands.Command) ([32]byte, bool) {
	switch c := cmd.(type) {
	case *commands.ReplicaWrite:
		return *c.BoxID, true
	case *commands.ReplicaMessage:
		return *c.EnvelopeHash(), true
	default:
		return [32]byte{}, false
	}
}

func (co *Connector) DispatchCommand(cmd commands.Command, idHash *[32]byte) {
	co.RLock()
	c, ok := co.conns[*idHash]
	co.RUnlock()

	if cmd == nil {
		co.log.Error("Dropping command: command is nil, wtf")
		return
	}

	if ok {
		// Connection exists - dispatch immediately
		co.log.Debugf("Dispatching command type %T to peer %x", cmd, idHash)
		c.dispatchCommand(cmd)
	} else {
		// No connection - add to retry queue instead of dropping
		co.log.Warningf("No connection for destination %x, queueing %T for retry", idHash[:8], cmd)
		co.QueueForRetry(cmd, *idHash)
	}
}

// QueueForRetry adds a command to the retry queue when no connection is available.
// Dedup is by (destination replica, BoxID): re-queuing the same write collapses
// and bumps attempts; writes for different boxes to the same peer accumulate as
// distinct entries. Evicts expired entries and, if at capacity, the oldest entry.
func (co *Connector) QueueForRetry(cmd commands.Command, idHash [32]byte) {
	co.retryQueueMu.Lock()
	defer co.retryQueueMu.Unlock()

	co.pruneRetryQueueLocked()

	ident, hasIdent := cmdIdentity(cmd)

	peerCount := 0
	for i, rc := range co.retryQueue {
		if rc.idHash != idHash {
			continue
		}
		peerCount++
		if hasIdent && rc.hasIdent && rc.ident == ident {
			co.retryQueue[i].cmd = cmd
			co.retryQueue[i].lastTry = time.Now()
			co.retryQueue[i].attempts++
			co.log.Debugf("Updated retry queue entry for peer %x ident %x, attempt %d", idHash[:8], ident[:8], co.retryQueue[i].attempts)
			instrument.RetryQueueSize(len(co.retryQueue))
			return
		}
	}

	if peerCount >= maxRetryQueuePerPeer {
		// Evict the oldest entry for this peer (leaves other peers' entries alone).
		for i, rc := range co.retryQueue {
			if rc.idHash == idHash {
				co.log.Warningf("Retry queue at per-peer capacity (%d) for peer %x; evicting oldest entry (ident %x)", maxRetryQueuePerPeer, idHash[:8], rc.ident[:8])
				co.retryQueue = append(co.retryQueue[:i], co.retryQueue[i+1:]...)
				instrument.RetryQueueDropped("capacity")
				break
			}
		}
	}

	now := time.Now()
	co.retryQueue = append(co.retryQueue, retryCommand{
		cmd:       cmd,
		idHash:    idHash,
		ident:     ident,
		hasIdent:  hasIdent,
		attempts:  1,
		firstSeen: now,
		lastTry:   now,
	})
	instrument.RetryQueueSize(len(co.retryQueue))
}

// pruneRetryQueueLocked drops entries older than retryTTL. Must hold retryQueueMu.
func (co *Connector) pruneRetryQueueLocked() {
	if len(co.retryQueue) == 0 {
		return
	}
	now := time.Now()
	j := 0
	for i, rc := range co.retryQueue {
		if now.Sub(rc.firstSeen) > retryTTL {
			co.log.Warningf("Dropping expired retry: peer %x ident %x age %s attempts %d", rc.idHash[:8], rc.ident[:8], now.Sub(rc.firstSeen), rc.attempts)
			instrument.RetryQueueDropped("ttl")
			continue
		}
		if i != j {
			co.retryQueue[j] = rc
		}
		j++
	}
	co.retryQueue = co.retryQueue[:j]
}

// processRetryQueue attempts to dispatch queued commands when connections become available
func (co *Connector) processRetryQueue() {
	co.retryQueueMu.Lock()
	defer co.retryQueueMu.Unlock()

	co.pruneRetryQueueLocked()

	if len(co.retryQueue) == 0 {
		instrument.RetryQueueSize(0)
		return
	}

	co.log.Debugf("Processing retry queue with %d commands", len(co.retryQueue))

	// Process retry queue in reverse order to safely remove items
	for i := len(co.retryQueue) - 1; i >= 0; i-- {
		retryCmd := co.retryQueue[i]

		// Check if connection is now available
		co.RLock()
		c, ok := co.conns[retryCmd.idHash]
		co.RUnlock()

		if ok {
			// Connection available - dispatch the command
			co.log.Debugf("Retrying %T for peer %x ident %x after %d attempts", retryCmd.cmd, retryCmd.idHash[:8], retryCmd.ident[:8], retryCmd.attempts)
			c.dispatchCommand(retryCmd.cmd)

			// Remove from retry queue
			co.retryQueue = append(co.retryQueue[:i], co.retryQueue[i+1:]...)
		}
	}
	instrument.RetryQueueSize(len(co.retryQueue))
}

func (co *Connector) DispatchReplication(cmd *commands.ReplicaWrite) {
	co.Go(func() {
		start := time.Now()
		// Acquire semaphore slot (or bail on shutdown)
		select {
		case <-co.HaltCh():
			return
		case co.replicationSem <- struct{}{}:
		}
		defer func() { <-co.replicationSem }()
		co.doReplication(cmd)
		instrument.ReplicationLatency(time.Since(start).Seconds())
	})
}

func (co *Connector) doReplication(cmd *commands.ReplicaWrite) {
	doc := co.server.PKIWorker.LastCachedPKIDocument()
	if doc == nil {
		co.log.Error("REPLICATION: Failed - no PKI document available")
		return
	}

	// Log our own identity for context
	myIdBytes, err := co.server.identityPublicKey.MarshalBinary()
	if err != nil {
		co.log.Errorf("REPLICATION: Failed to marshal identity key: %v", err)
		return
	}
	myIdHash := blake2b.Sum256(myIdBytes)
	co.log.Infof("REPLICATION: My identity: %x", myIdHash[:8])

	// Get ALL shards for this BoxID (not just remote ones)
	// This ensures we replicate to both shard replicas
	allShards, err := replicaCommon.GetShards(cmd.BoxID, doc)
	if err != nil {
		co.log.Errorf("REPLICATION: Failed - GetShards err: %v", err)
		panic(err)
	}

	if len(allShards) == 0 {
		co.log.Warningf("REPLICATION: No shards available for BoxID %x", cmd.BoxID)
		return
	}

	// Track replication success/failure
	successCount := 0
	totalTargets := 0

	for _, desc := range allShards {
		idHash := blake2b.Sum256(desc.IdentityKey)

		// Skip self - we already wrote locally
		if hmac.Equal(idHash[:], myIdHash[:]) {
			co.log.Debugf("REPLICATION: Skipping self for BoxID %x", cmd.BoxID)
			continue
		}

		totalTargets++

		// Check if connection exists before dispatching
		co.RLock()
		_, hasConnection := co.conns[idHash]
		co.RUnlock()

		if hasConnection {
			successCount++
		}

		co.DispatchCommand(cmd, &idHash)
		instrument.ReplicationDispatched()
	}

	if totalTargets == 0 {
		co.log.Infof("REPLICATION: No remote shards needed for BoxID %x (we are the only shard)", cmd.BoxID)
		return
	}

	if successCount == totalTargets {
		co.log.Infof("REPLICATION: Successfully dispatched to all %d targets for BoxID %x", totalTargets, cmd.BoxID)
	} else {
		co.log.Warningf("REPLICATION: Only dispatched to %d/%d targets for BoxID %x (others queued for retry)", successCount, totalTargets, cmd.BoxID)
	}
}

func (co *Connector) worker() {
	// Create a dedicated logger for this goroutine (go-logging requires one logger per goroutine)
	log := co.server.LogBackend().GetLogger("replica connectorWorker")

	var (
		resweepInterval = epochtime.Period / 8
	)

	log.Debug("Starting connector worker")

	// Try to spawn connections immediately on startup rather than waiting.
	// This helps replicas connect to each other more promptly when the PKI
	// document is already available.
	co.spawnNewConns()
	co.processRetryQueue()

	timer := time.NewTimer(resweepInterval)
	defer timer.Stop()

	for {
		timerFired := false
		select {
		case <-co.HaltCh():
			log.Debugf("Connector worker terminating gracefully.")
			return
		case <-co.forceUpdateCh:
			log.Debug("Forced connection update triggered")
		case <-timer.C:
			timerFired = true
		}
		if !timerFired && !timer.Stop() {
			<-timer.C
		}

		// Start outgoing connections as needed, based on the PKI documents
		// and current time.
		co.spawnNewConns()

		// Process retry queue after spawning new connections
		co.processRetryQueue()

		timer.Reset(resweepInterval)
	}

	// NOTREACHED
}

func (co *Connector) spawnNewConns() {
	newPeerMap := co.server.PKIWorker.ReplicasCopy()

	// Traverse the connection table, to figure out which peers are actually
	// new.  Each outgoingConn object is responsible for determining when
	// the connection is stale.
	co.RLock()
	for id := range newPeerMap {
		if _, ok := co.conns[id]; ok {
			// There's a connection object for the peer already.
			delete(newPeerMap, id)
		}
	}
	co.RUnlock()

	// Spawn the new outgoingConn objects.
	// Connect to all replicas for replication purposes
	for id, v := range newPeerMap {
		co.log.Debugf("Spawning connection to: '%x'.", id)

		scheme := schemes.ByName(co.server.cfg.WireKEMScheme)
		if scheme == nil {
			panic("KEM scheme not found in registry")
		}

		c := newOutgoingConn(co, v, co.server.cfg.SphinxGeometry, scheme)
		co.onNewConn(c)
	}
}

func (co *Connector) CloseAllCh() chan interface{} {
	return co.closeAllCh
}

// ConnectionCount returns the number of active outgoing connections.
func (co *Connector) ConnectionCount() int {
	co.RLock()
	defer co.RUnlock()
	return len(co.conns)
}

func (co *Connector) onNewConn(c *outgoingConn) {
	nodeID := hash.Sum256(c.dst.IdentityKey)

	co.closeAllWg.Add(1)
	co.Lock()
	defer func() {
		co.Unlock()
		go c.worker()
	}()
	if _, ok := co.conns[nodeID]; ok {
		// This should NEVER happen.  Not sure what the sensible thing to do is.
		co.log.Warningf("Connection to peer: '%x' already exists.", nodeID)
	}
	co.conns[nodeID] = c

	// Process retry queue when a new connection is established
	go func() {
		// Small delay to ensure connection is fully established
		time.Sleep(100 * time.Millisecond)
		co.processRetryQueue()
	}()
}

func (co *Connector) OnClosedConn(c *outgoingConn) {
	nodeID := hash.Sum256(c.dst.IdentityKey)

	co.Lock()
	defer func() {
		co.Unlock()
		co.closeAllWg.Done()
	}()
	delete(co.conns, nodeID)
}

// New creates a new Connector.
func newConnector(server *Server) *Connector {
	co := &Connector{
		server:        server,
		log:           server.LogBackend().GetLogger("replica Connector"),
		conns:         make(map[[constants.NodeIDLength]byte]*outgoingConn),
		replicationSem: make(chan struct{}, server.cfg.MaxConcurrentReplications),
		forceUpdateCh:  make(chan interface{}, 1), // See forceUpdate().
		closeAllCh:    make(chan interface{}),
	}

	co.Go(co.worker)
	return co
}

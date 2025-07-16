// SPDX-FileCopyrightText: Copyright (C) 2017  Yawning Angel.
// SPDX-License-Identifier: AGPL-3.0-only

package replica

import (
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
)

type Connector struct {
	sync.RWMutex
	worker.Worker

	server *Server
	log    *logging.Logger

	conns         map[[constants.NodeIDLength]byte]*outgoingConn
	forceUpdateCh chan interface{}

	replicationCh chan *commands.ReplicaWrite

	// Retry queue for commands that couldn't be dispatched due to missing connections
	retryQueue   []retryCommand
	retryQueueMu sync.Mutex

	closeAllCh chan interface{}
	closeAllWg sync.WaitGroup
}

// retryCommand holds a command that needs to be retried when connections become available
type retryCommand struct {
	cmd      commands.Command
	idHash   [32]byte
	attempts int
	lastTry  time.Time
}

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

func getBoxID(cmd commands.Command) *[32]byte {
	switch myCmd := cmd.(type) {
	case *commands.ReplicaWrite:
		return myCmd.BoxID
	default:
		panic("invalid command")
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
		co.log.Warningf("No connection for destination %x, queueing command for retry: %v", idHash[:8], getBoxID(cmd))
		co.queueForRetry(cmd, *idHash)
	}
}

// queueForRetry adds a command to the retry queue when no connection is available
func (co *Connector) queueForRetry(cmd commands.Command, idHash [32]byte) {
	const maxRetryAttempts = 5

	co.retryQueueMu.Lock()
	defer co.retryQueueMu.Unlock()

	// Check if we already have this command in the retry queue
	for i, retryCmd := range co.retryQueue {
		if retryCmd.idHash == idHash {
			// Update existing entry
			co.retryQueue[i].cmd = cmd
			co.retryQueue[i].lastTry = time.Now()
			if co.retryQueue[i].attempts < maxRetryAttempts {
				co.retryQueue[i].attempts++
				co.log.Debugf("Updated retry queue entry for %x, attempt %d/%d", idHash[:8], co.retryQueue[i].attempts, maxRetryAttempts)
			} else {
				co.log.Errorf("Max retry attempts (%d) reached for destination %x, dropping command: %v", maxRetryAttempts, idHash[:8], getBoxID(cmd))
				// Remove from retry queue
				co.retryQueue = append(co.retryQueue[:i], co.retryQueue[i+1:]...)
			}
			return
		}
	}

	// Add new entry to retry queue
	retryCmd := retryCommand{
		cmd:      cmd,
		idHash:   idHash,
		attempts: 1,
		lastTry:  time.Now(),
	}
	co.retryQueue = append(co.retryQueue, retryCmd)
}

// processRetryQueue attempts to dispatch queued commands when connections become available
func (co *Connector) processRetryQueue() {
	co.retryQueueMu.Lock()
	defer co.retryQueueMu.Unlock()

	if len(co.retryQueue) == 0 {
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
			co.log.Debugf("Retrying command for %x after %d attempts", retryCmd.idHash[:8], retryCmd.attempts)
			c.dispatchCommand(retryCmd.cmd)

			// Remove from retry queue
			co.retryQueue = append(co.retryQueue[:i], co.retryQueue[i+1:]...)
		}
	}
}

func (co *Connector) DispatchReplication(cmd *commands.ReplicaWrite) {
	co.replicationCh <- cmd
}

func (co *Connector) doReplication(cmd *commands.ReplicaWrite) {
	doc := co.server.PKIWorker.PKIDocument()
	if doc == nil {
		co.log.Error("REPLICATION: Failed - no PKI document available")
		return
	}

	// Log our own identity for context
	myIdBytes, err := co.server.identityPublicKey.MarshalBinary()
	if err != nil {
		co.log.Errorf("REPLICATION: Failed to marshal identity key: %v", err)
	} else {
		myIdHash := blake2b.Sum256(myIdBytes)
		co.log.Infof("REPLICATION: My identity: %x", myIdHash[:8])
	}

	descs, err := replicaCommon.GetRemoteShards(co.server.identityPublicKey, cmd.BoxID, doc)
	if err != nil {
		co.log.Errorf("REPLICATION: Failed - GetRemoteShards err: %v", err)
		panic(err)
	}

	if len(descs) == 0 {
		co.log.Infof("REPLICATION: No remote shards needed for BoxID %x", cmd.BoxID)
		return
	}

	// Track replication success/failure
	successCount := 0
	totalTargets := len(descs)

	for _, desc := range descs {
		idHash := blake2b.Sum256(desc.IdentityKey)

		// Check if connection exists before dispatching
		co.RLock()
		_, hasConnection := co.conns[idHash]
		co.RUnlock()

		if hasConnection {
			successCount++
		}

		co.DispatchCommand(cmd, &idHash)
	}

	if successCount == totalTargets {
		co.log.Infof("REPLICATION: Successfully dispatched to all %d targets for BoxID %x", totalTargets, cmd.BoxID)
	} else {
		co.log.Warningf("REPLICATION: Only dispatched to %d/%d targets for BoxID %x (others queued for retry)", successCount, totalTargets, cmd.BoxID)
	}
}

func (co *Connector) replicationWorker() {
	co.log.Infof("REPLICATION: Starting replication worker")
	for {
		select {
		case <-co.HaltCh():
			co.log.Infof("REPLICATION: Worker terminating gracefully")
			return
		case writeCmd := <-co.replicationCh:
			co.log.Infof("REPLICATION: Worker received write command for BoxID: %x", writeCmd.BoxID)
			co.doReplication(writeCmd)
		}
	}
}

func (co *Connector) worker() {
	var (
		initialSpawnDelay = epochtime.Period / 64
		resweepInterval   = epochtime.Period / 8
	)

	co.log.Debug("Starting connector worker")
	timer := time.NewTimer(initialSpawnDelay)
	defer timer.Stop()

	for {
		timerFired := false
		select {
		case <-co.HaltCh():
			co.log.Debugf("Connector worker terminating gracefully.")
			return
		case <-co.forceUpdateCh:
			co.log.Debug("Forced connection update triggered")
		case <-timer.C:
			timerFired = true
			co.log.Debug("Periodic connection update triggered")
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
		replicationCh: make(chan *commands.ReplicaWrite, server.cfg.ReplicationQueueLength),
		forceUpdateCh: make(chan interface{}, 1), // See forceUpdate().
		closeAllCh:    make(chan interface{}),
	}

	co.Go(co.worker)
	co.Go(co.replicationWorker)
	return co
}

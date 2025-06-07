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
	"github.com/katzenpost/katzenpost/replica/common"
)

type Connector struct {
	sync.RWMutex
	worker.Worker

	server *Server
	log    *logging.Logger

	conns         map[[constants.NodeIDLength]byte]*outgoingConn
	forceUpdateCh chan interface{}

	replicationCh chan *commands.ReplicaWrite

	closeAllCh chan interface{}
	closeAllWg sync.WaitGroup
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
	case *common.ReplicaRead:
		return myCmd.BoxID
	case *commands.ReplicaWrite:
		return myCmd.BoxID
	default:
		panic("invalid command")
	}
}

func (co *Connector) DispatchCommand(cmd commands.Command, idHash *[32]byte) {
	co.RLock()
	defer co.RUnlock()

	if cmd == nil {
		co.log.Error("Dropping command: command is nil, wtf")
		return
	}
	c, ok := co.conns[*idHash]
	if !ok {
		co.log.Debugf("Dropping command: %v (No connection for destination)", getBoxID(cmd))
		return
	}

	co.log.Debugf("Dispatching command type %T to peer %x", cmd, idHash)
	c.dispatchCommand(cmd)
}

func (co *Connector) DispatchReplication(cmd *commands.ReplicaWrite) {
	co.log.Debugf("Queueing replication for BoxID: %x", cmd.BoxID)
	co.replicationCh <- cmd
}

func (co *Connector) doReplication(cmd *commands.ReplicaWrite) {
	co.log.Debugf("Starting replication for BoxID: %x", cmd.BoxID)
	doc := co.server.PKIWorker.PKIDocument()
	descs, err := common.GetRemoteShards(co.server.identityPublicKey, cmd.BoxID, doc)
	if err != nil {
		co.log.Errorf("Replication failed: GetShards err: %v", err)
		panic(err)
	}
	co.log.Debugf("Found %d remote shards for replication", len(descs))
	for _, desc := range descs {
		idHash := blake2b.Sum256(desc.IdentityKey)
		co.log.Debugf("Dispatching replication to shard %x", idHash)
		co.DispatchCommand(cmd, &idHash)
	}
	co.log.Debug("Replication dispatch completed")
}

func (co *Connector) replicationWorker() {
	co.log.Debug("Starting replication worker")
	for {
		select {
		case <-co.HaltCh():
			co.log.Debugf("Replication worker terminating gracefully.")
			return
		case writeCmd := <-co.replicationCh:
			co.log.Debugf("Replication worker received write command for BoxID: %x", writeCmd.BoxID)
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

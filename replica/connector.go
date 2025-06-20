// SPDX-FileCopyrightText: Copyright (C) 2017  Yawning Angel.
// SPDX-License-Identifier: AGPL-3.0-only

package replica

import (
	"fmt"
	"sync"
	"time"

	replicaCommon "github.com/katzenpost/katzenpost/replica/common"

	"golang.org/x/crypto/blake2b"
	"gopkg.in/op/go-logging.v1"

	"github.com/katzenpost/hpqc/hash"
	"github.com/katzenpost/hpqc/kem/schemes"

	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/katzenpost/core/wire/commands"
	"github.com/katzenpost/katzenpost/core/worker"
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
	co.log.Infof("REPLICATION: Queueing replication for BoxID: %x", cmd.BoxID)
	fmt.Printf("REPLICATION: Queueing replication for BoxID: %x\n", cmd.BoxID)
	co.replicationCh <- cmd
}

func (co *Connector) doReplication(cmd *commands.ReplicaWrite) {
	co.log.Infof("REPLICATION: Starting replication for BoxID: %x", cmd.BoxID)
	fmt.Printf("REPLICATION: Starting replication for BoxID: %x\n", cmd.BoxID)

	doc := co.server.PKIWorker.PKIDocument()
	if doc == nil {
		co.log.Error("REPLICATION: Failed - no PKI document available")
		fmt.Printf("REPLICATION: Failed - no PKI document available\n")
		return
	}

	// Log our own identity for context
	myIdBytes, err := co.server.identityPublicKey.MarshalBinary()
	if err != nil {
		co.log.Errorf("REPLICATION: Failed to marshal identity key: %v", err)
		fmt.Printf("REPLICATION: Failed to marshal identity key: %v\n", err)
	} else {
		myIdHash := blake2b.Sum256(myIdBytes)
		co.log.Infof("REPLICATION: My identity: %x", myIdHash[:8])
		fmt.Printf("REPLICATION: My identity: %x\n", myIdHash[:8])
	}

	descs, err := replicaCommon.GetRemoteShards(co.server.identityPublicKey, cmd.BoxID, doc)
	if err != nil {
		co.log.Errorf("REPLICATION: Failed - GetRemoteShards err: %v", err)
		fmt.Printf("REPLICATION: Failed - GetRemoteShards err: %v\n", err)
		panic(err)
	}

	co.log.Infof("REPLICATION: Found %d remote shards for BoxID %x", len(descs), cmd.BoxID)
	fmt.Printf("REPLICATION: Found %d remote shards for BoxID %x\n", len(descs), cmd.BoxID)

	if len(descs) == 0 {
		co.log.Infof("REPLICATION: No remote shards needed for BoxID %x", cmd.BoxID)
		fmt.Printf("REPLICATION: No remote shards needed for BoxID %x\n", cmd.BoxID)
		return
	}

	for i, desc := range descs {
		idHash := blake2b.Sum256(desc.IdentityKey)
		co.log.Infof("REPLICATION: Dispatching to shard %d/%d: %s (ID: %x)", i+1, len(descs), desc.Name, idHash[:8])
		fmt.Printf("REPLICATION: Dispatching to shard %d/%d: %s (ID: %x)\n", i+1, len(descs), desc.Name, idHash[:8])
		co.DispatchCommand(cmd, &idHash)
	}

	co.log.Infof("REPLICATION: Dispatch completed for BoxID %x", cmd.BoxID)
	fmt.Printf("REPLICATION: Dispatch completed for BoxID %x\n", cmd.BoxID)
}

func (co *Connector) replicationWorker() {
	co.log.Infof("REPLICATION: Starting replication worker")
	fmt.Printf("REPLICATION: Starting replication worker\n")
	for {
		select {
		case <-co.HaltCh():
			co.log.Infof("REPLICATION: Worker terminating gracefully")
			fmt.Printf("REPLICATION: Worker terminating gracefully\n")
			return
		case writeCmd := <-co.replicationCh:
			co.log.Infof("REPLICATION: Worker received write command for BoxID: %x", writeCmd.BoxID)
			fmt.Printf("REPLICATION: Worker received write command for BoxID: %x\n", writeCmd.BoxID)
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

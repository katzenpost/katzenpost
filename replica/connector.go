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
	"github.com/katzenpost/katzenpost/core/utils"
	"github.com/katzenpost/katzenpost/core/wire/commands"
	"github.com/katzenpost/katzenpost/core/worker"
	"github.com/katzenpost/katzenpost/replica/common"
)

// XXX FIXME TODO(david): make this a config param?
const replicationQueueLength = 100

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

func getBoxID(cmd commands.Command) *[32]byte {
	switch myCmd := cmd.(type) {
	case *commands.ReplicaRead:
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

	c.dispatchCommand(cmd)
}

func (co *Connector) DispatchReplication(cmd *commands.ReplicaWrite) {
	co.replicationCh <- cmd
}

func (co *Connector) doReplication(cmd *commands.ReplicaWrite) {
	doc := co.server.pkiWorker.PKIDocument()
	descs, err := common.GetRemoteShards(co.server.identityPublicKey, cmd.BoxID, doc)
	if err != nil {
		co.log.Errorf("handleReplicaMessage failed: GetShards err: %x", err)
		panic(err)
	}
	for _, desc := range descs {
		idHash := blake2b.Sum256(desc.IdentityKey)
		co.DispatchCommand(cmd, &idHash)
	}
}

func (co *Connector) replicationWorker() {
	for {
		select {
		case <-co.HaltCh():
			co.log.Debugf("Replication worker terminating gracefully.")
			return
		case writeCmd := <-co.replicationCh:
			co.doReplication(writeCmd)
		}
	}
}

func (co *Connector) worker() {
	var (
		initialSpawnDelay = epochtime.Period / 64
		resweepInterval   = epochtime.Period / 8
	)

	timer := time.NewTimer(initialSpawnDelay)
	defer timer.Stop()

	for {
		timerFired := false
		select {
		case <-co.HaltCh():
			co.log.Debugf("Connector worker terminating gracefully.")
			return
		case <-co.forceUpdateCh:
		case <-timer.C:
			timerFired = true
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
	newPeerMap := co.server.pkiWorker.replicas.Copy()

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
		co.log.Warningf("Connection to peer: '%v' already exists.", utils.NodeIDToPrintString(&nodeID))
	}
	co.conns[nodeID] = c
}

func (co *Connector) onClosedConn(c *outgoingConn) {
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
		log:           server.LogBackend().GetLogger("Connector"),
		conns:         make(map[[constants.NodeIDLength]byte]*outgoingConn),
		replicationCh: make(chan *commands.ReplicaWrite, replicationQueueLength),
		forceUpdateCh: make(chan interface{}, 1), // See forceUpdate().
		closeAllCh:    make(chan interface{}),
	}

	co.Go(co.worker)
	co.Go(co.replicationWorker)
	return co
}

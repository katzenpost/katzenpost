// SPDX-FileCopyrightText: © 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"errors"
	"sync"
	"time"

	"gopkg.in/op/go-logging.v1"

	"github.com/katzenpost/hpqc/hash"
	"github.com/katzenpost/hpqc/kem/schemes"

	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/katzenpost/core/utils"
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

	closeAllCh chan interface{}
	closeAllWg sync.WaitGroup
}

func (co *Connector) destToNodeID(dest uint8) (*[constants.NodeIDLength]byte, error) {
	doc := co.server.pki.PKIDocument()
	if int(dest) >= (len(doc.StorageReplicas) - 1) {
		return nil, errors.New("invalid destination ID")
	}
	replica := doc.StorageReplicas[dest]
	idKeyHash := hash.Sum256(replica.IdentityKey)
	return &idKeyHash, nil
}

func (co *Connector) DispatchMessage(dest uint8, message *commands.ReplicaMessage) {
	id, err := co.destToNodeID(dest)
	if err != nil {
		co.log.Errorf("DispatchMessage failure: %s", err)
		return
	}

	co.RLock()
	c, ok := co.conns[*id]
	if !ok {
		co.RUnlock()
		co.log.Error("DispatchMessage failure: connection not found")
		return
	}
	co.RUnlock()
	c.dispatchMessage(message)
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

func (co *Connector) worker() {
	co.log.Debug("Connector worker thread started.")

	var (
		initialSpawnDelay = epochtime.Period / 64
		resweepInterval   = epochtime.Period / 8
	)

	co.log.Debugf("initialSpawnDelay is %v", initialSpawnDelay)

	timer := time.NewTimer(initialSpawnDelay)
	defer timer.Stop()

	for {
		co.log.Debug("BEFORE Connector worker thread select statement.")
		timerFired := false
		select {
		case <-co.HaltCh():
			co.log.Debugf("Connector worker terminating gracefully.")
			return
		case <-co.forceUpdateCh:
		case <-timer.C:
			timerFired = true
		}

		co.log.Debug("AFTER Connector select statement.")

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
	co.log.Debug("START spawnNewConns")
	newPeerMap := co.server.pki.ReplicasCopy()

	co.log.Debugf("spawnNewConns newPeerMap len %d", len(newPeerMap))

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

		c := newOutgoingConn(co, v, co.server.cfg)
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
		co.log.Warningf("Connection to peer: '%v' already exists.", utils.NodeIDToPrintString(&nodeID))
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
		log:           server.LogBackend().GetLogger("Connector"),
		conns:         make(map[[constants.NodeIDLength]byte]*outgoingConn),
		forceUpdateCh: make(chan interface{}, 1), // See forceUpdate().
		closeAllCh:    make(chan interface{}),
	}

	co.Go(co.worker)
	return co
}

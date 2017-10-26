// connector.go - Katzenpost server connector.
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
	"sync"
	"time"

	"github.com/katzenpost/core/sphinx/constants"
	"github.com/op/go-logging"
)

type connector struct {
	sync.RWMutex
	sync.WaitGroup

	s   *Server
	log *logging.Logger

	conns map[[constants.NodeIDLength]byte]*outgoingConn

	haltCh        chan interface{}
	forceUpdateCh chan interface{}

	closeAllCh chan interface{}
	closeAllWg sync.WaitGroup
}

func (co *connector) halt() {
	close(co.haltCh)
	co.Wait()

	// Close all outgoing connections.
	close(co.closeAllCh)
	co.closeAllWg.Wait()
}

func (co *connector) forceUpdate() {
	// This deliberately uses a non-blocking write to a buffered channel so
	// that the resweeps happen reliably.  Since the resweep is comprehensive,
	// there's no benefit to queueing more than one resweep request, and the
	// periodic timer serves as a fallback.
	select {
	case co.forceUpdateCh <- true:
	default:
	}
}

func (co *connector) dispatchPacket(pkt *packet) {
	co.RLock()
	defer co.RUnlock()

	c, ok := co.conns[pkt.nextNodeHop.ID]
	if !ok {
		co.log.Debugf("Dropping packet: %v (No connection for destination)", pkt.id)
		pkt.dispose()
		return
	}

	c.dispatchPacket(pkt)
}

func (co *connector) worker() {
	const (
		initialSpawnDelay = 15 * time.Second
		resweepInterval   = 3 * time.Minute
	)

	timer := time.NewTimer(initialSpawnDelay)
	defer func() {
		timer.Stop()
		co.Done()
	}()
	for {
		timerFired := false
		select {
		case <-co.haltCh:
			co.log.Debugf("Terminating gracefully.")
			return
		case <-co.forceUpdateCh:
			co.log.Debugf("Starting forced sweep.")
		case <-timer.C:
			co.log.Debugf("Starting periodic sweep.")
			timerFired = true
		}
		if !timerFired && !timer.Stop() {
			<-timer.C
		}

		// Start outgoing connections as needed, based on the PKI documents
		// and current time.
		co.spawnNewConns()

		co.log.Debugf("Done with sweep.")
		timer.Reset(resweepInterval)
	}

	// NOTREACHED
}

func (co *connector) spawnNewConns() {
	newPeerMap := co.s.pki.outgoingDestinations()

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
		co.log.Debugf("Spawning connection to: '%v'.", nodeIDToPrintString(&id))
		c := newOutgoingConn(co, v)
		co.onNewConn(c)
	}
}

func (co *connector) onNewConn(c *outgoingConn) {
	nodeID := c.dst.IdentityKey.ByteArray()

	co.closeAllWg.Add(1)
	co.Lock()
	defer func() {
		co.Unlock()
		go c.worker()
	}()
	if _, ok := co.conns[nodeID]; ok {
		// This should NEVER happen.  Not sure what the sensible thing to do is.
		co.log.Warningf("Connection to peer: '%v' already exists.", nodeIDToPrintString(&nodeID))
	}
	co.conns[nodeID] = c
}

func (co *connector) onClosedConn(c *outgoingConn) {
	nodeID := c.dst.IdentityKey.ByteArray()

	co.Lock()
	defer func() {
		co.Unlock()
		co.closeAllWg.Done()
	}()
	delete(co.conns, nodeID)
}

func newConnector(s *Server) *connector {
	co := new(connector)
	co.s = s
	co.log = s.logBackend.GetLogger("connector")
	co.conns = make(map[[constants.NodeIDLength]byte]*outgoingConn)
	co.haltCh = make(chan interface{})
	co.forceUpdateCh = make(chan interface{}, 1) // See forceUpdate().
	co.closeAllCh = make(chan interface{})
	co.Add(1)

	go co.worker()
	return co
}

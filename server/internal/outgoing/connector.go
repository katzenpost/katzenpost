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

// Package outgoing implements the outgoing connection support.
package outgoing

import (
	"sync"
	"time"

	"gopkg.in/op/go-logging.v1"

	"github.com/katzenpost/hpqc/hash"
	"github.com/katzenpost/hpqc/kem/schemes"

	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/katzenpost/core/worker"
	"github.com/katzenpost/katzenpost/server/internal/debug"
	"github.com/katzenpost/katzenpost/server/internal/glue"
	"github.com/katzenpost/katzenpost/server/internal/instrument"
	"github.com/katzenpost/katzenpost/server/internal/packet"
)

type connector struct {
	sync.RWMutex
	worker.Worker

	glue glue.Glue
	log  *logging.Logger

	conns         map[[constants.NodeIDLength]byte]*outgoingConn
	forceUpdateCh chan interface{}

	closeAllCh chan interface{}
	closeAllWg sync.WaitGroup
}

func (co *connector) Halt() {
	co.Worker.Halt()

	// Close all outgoing connections.
	close(co.closeAllCh)
	co.closeAllWg.Wait()
}

func (co *connector) ForceUpdate() {
	// This deliberately uses a non-blocking write to a buffered channel so
	// that the resweeps happen reliably.  Since the resweep is comprehensive,
	// there's no benefit to queueing more than one resweep request, and the
	// periodic timer serves as a fallback.
	select {
	case co.forceUpdateCh <- true:
	}
}

func (co *connector) DispatchPacket(pkt *packet.Packet) {
	co.RLock()
	defer co.RUnlock()

	if pkt == nil {
		co.log.Debug("Dropping packet: packet is nil, wtf")
		instrument.InvalidPacketsDropped()
		instrument.PacketsDropped()
		pkt.Dispose()
		return
	}
	if pkt.NextNodeHop == nil {
		co.log.Debug("Dropping packet: packet NextNodeHop is nil, wtf")
		instrument.InvalidPacketsDropped()
		instrument.PacketsDropped()
		pkt.Dispose()
		return
	}
	c, ok := co.conns[pkt.NextNodeHop.ID]
	if !ok {
		co.log.Debugf("Dropping packet: %v (No connection for destination)", pkt.ID)
		instrument.OutgoingPacketsDropped()
		instrument.PacketsDropped()
		pkt.Dispose()
		return
	}

	c.dispatchPacket(pkt)
}

func (co *connector) worker() {
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
			co.log.Debugf("Terminating gracefully.")
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

func (co *connector) spawnNewConns() {
	newPeerMap := co.glue.PKI().OutgoingDestinations()

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

		scheme := schemes.ByName(co.glue.Config().Server.WireKEM)
		if scheme == nil {
			panic("KEM scheme not found in registry")
		}

		c := newOutgoingConn(co, v, co.glue.Config().SphinxGeometry, scheme)
		co.onNewConn(c)
	}
}

func (co *connector) onNewConn(c *outgoingConn) {
	nodeID := hash.Sum256(c.dst.IdentityKey)

	co.closeAllWg.Add(1)
	co.Lock()
	defer func() {
		co.Unlock()
		go c.worker()
	}()
	if _, ok := co.conns[nodeID]; ok {
		// This should NEVER happen.  Not sure what the sensible thing to do is.
		co.log.Warningf("Connection to peer: '%v' already exists.", debug.NodeIDToPrintString(&nodeID))
	}
	co.conns[nodeID] = c
}

func (co *connector) onClosedConn(c *outgoingConn) {
	nodeID := hash.Sum256(c.dst.IdentityKey)

	co.Lock()
	defer func() {
		co.Unlock()
		co.closeAllWg.Done()
	}()
	delete(co.conns, nodeID)
}

func (co *connector) IsValidForwardDest(id *[constants.NodeIDLength]byte) bool {
	// This doesn't need to be super accurate, just enough to prevent packets
	// destined to la-la land from being scheduled.
	co.RLock()
	defer co.RUnlock()
	_, ok := co.conns[*id]
	return ok
}

// New creates a new connector.
func New(glue glue.Glue) glue.Connector {
	co := &connector{
		glue:          glue,
		log:           glue.LogBackend().GetLogger("connector"),
		conns:         make(map[[constants.NodeIDLength]byte]*outgoingConn),
		forceUpdateCh: make(chan interface{}, 1), // See forceUpdate().
		closeAllCh:    make(chan interface{}),
	}

	co.Go(co.worker)
	return co
}

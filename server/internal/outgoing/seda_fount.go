package outgoing

import (
	"net"

	"github.com/katzenpost/hpqc/hash"
	"github.com/katzenpost/hpqc/kem/schemes"
	"github.com/katzenpost/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/katzenpost/server/internal/debug"
	"github.com/katzenpost/katzenpost/server/internal/glue"
)

func NewSEDAFount(glue glue.Glue) (glue.Connector, net.Conn) {
	co := &connector{
		glue:          glue,
		log:           glue.LogBackend().GetLogger("connector"),
		conns:         make(map[[constants.NodeIDLength]byte]*outgoingConn),
		forceUpdateCh: make(chan interface{}, 1), // See forceUpdate().
		closeAllCh:    make(chan interface{}),
	}

	clientConn, serverConn := net.Pipe()

	co.Go(func() {
		co.selfTestWorker(serverConn)
	})
	return co, clientConn
}

func (co *connector) onNewTestConn(c *outgoingConn, serverConn net.Conn) {
	nodeID := hash.Sum256(c.dst.IdentityKey)

	co.closeAllWg.Add(1)
	co.Lock()

	defer func() {
		co.Unlock()
		go c.selftestWorker(serverConn)
	}()
	if _, ok := co.conns[nodeID]; ok {
		// This should NEVER happen.  Not sure what the sensible thing to do is.
		co.log.Warningf("Connection to peer: '%v' already exists.", debug.NodeIDToPrintString(&nodeID))
	}
	co.conns[nodeID] = c
}

func (co *connector) selfTestWorker(serverConn net.Conn) {
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
		co.onNewTestConn(c, serverConn)
	}
}

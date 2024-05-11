package incoming

import (
	"container/list"
	"fmt"
	"net"

	"github.com/katzenpost/katzenpost/server/internal/glue"
)

// NewSEDADrain is to be used for the SEDA self-test.
func NewSEDADrain(glue glue.Glue, inboundPacketsChan chan<- interface{}, id int) (*listener, net.Conn) {
	l := &listener{
		glue:       glue,
		log:        glue.LogBackend().GetLogger(fmt.Sprintf("listener:%d", id)),
		conns:      list.New(),
		incomingCh: inboundPacketsChan,
		closeAllCh: make(chan interface{}),
	}
	serverConn, clientConn := net.Pipe()
	l.Go(func() {
		l.onNewConn(serverConn)
	})
	return l, clientConn
}

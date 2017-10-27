// server.go - Noise based wire protocol.
// Copyright (C) 2017  David Anthony Stainton
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

// Package server provides the Katzenpost noise based server side wire protocol.
package server

import (
	"net"
	"sync"
	"time"

	"github.com/op/go-logging"
)

var log = logging.MustGetLogger("wire_server")

// Options is used to configure various properties of the wire protocol
// server handler. Default values are used when a nil Options pointer
// is passed to New.
type Options struct {
	maxConcurrency    int
	readWriteDeadline time.Time
}

var defaultOptions = Options{
	maxConcurrency:    10,
	readWriteDeadline: time.Time{},
}

// Server is the server wire protocol struct
// for our link layer.
type Server struct {
	options            *Options
	network            string
	address            string
	conns              []net.Conn
	listener           net.Listener
	waitGroup          *sync.WaitGroup
	stopping           bool
	connectionCallback func(net.Conn) error
}

// New creates a new Server given
// network, address strings and options
func New(network, address string, connectionCallback func(net.Conn) error, options *Options) *Server {
	wire := Server{
		network:            network,
		address:            address,
		stopping:           false,
		waitGroup:          &sync.WaitGroup{},
		connectionCallback: connectionCallback,
	}
	if options == nil {
		wire.options = &defaultOptions
	} else {
		wire.options = options
	}
	wire.conns = make([]net.Conn, 0, wire.options.maxConcurrency)
	return &wire
}

// Start the Server
func (w *Server) Start() error {
	var err error
	log.Debugf("starting server %s:%s", w.network, w.address)
	w.listener, err = net.Listen(w.network, w.address)
	if err != nil {
		return err
	}
	w.waitGroup.Add(1)
	go w.acceptLoop()
	return nil
}

// Stop will kill our listener and all it's connections
func (w *Server) Stop() {
	log.Debugf("stopping server %s:%s", w.network, w.address)
	w.stopping = true
	if w.listener != nil {
		err := w.listener.Close()
		if err != nil {
			log.Debugf("failed to close: %s", err)
		}
		w.closeConns(w.conns)
	}
	w.waitGroup.Wait()
}

func (w *Server) closeConns(conns []net.Conn) {
	for i, conn := range conns {
		if conn != nil {
			log.Debugf("Closing connection #%d", i)
			err := conn.Close()
			if err != nil {
				log.Debugf("failed to close: %s", err)
			}
		}
	}
}

// acceptLoop is called by our Start method
func (w *Server) acceptLoop() {
	defer w.waitGroup.Done()
	defer w.closeConns(w.conns)
	defer func() {
		log.Debugf("acceptLoop stopping for listener service %s:%s", w.network, w.address)
		err := w.listener.Close()
		if err != nil {
			log.Debugf("failed to close: %s", err)
		}
	}()

	for {
		conn, err := w.listener.Accept()
		if err != nil {
			log.Errorf("server connection accept failure: %s\n", err)
			if !w.stopping {
				continue
			}
			return
		}
		if len(w.conns) == w.options.maxConcurrency {
			log.Error("server max concurrency reached. closing new connection.")
			err = conn.Close()
			if err != nil {
				log.Debugf("failed to close: %s", err)
			}
			continue
		}
		err = conn.SetDeadline(w.options.readWriteDeadline)
		if err != nil {
			log.Debugf("failed to set deadline: %s", err)
		}
		w.conns = append(w.conns, conn)
		go w.handleConnection(conn, len(w.conns)-1)
	}
}

// handleConnection is called implicitly by our Start method via our
// acceptLoop method
func (w *Server) handleConnection(conn net.Conn, id int) {
	defer func() {
		log.Debugf("Closing connection #%d", id)
		err := conn.Close()
		if err != nil {
			log.Debugf("failed to close: %s", err)
		}
		w.conns[id] = nil
	}()

	log.Debugf("Starting connection #%d", id)
	if err := w.connectionCallback(conn); err != nil {
		log.Debugf(err.Error())
	}
}

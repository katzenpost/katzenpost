// thwack.go - Trivial text based management protocol.
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

// Package thwack provides a trivial text based management protocol.
package thwack

import (
	"fmt"
	"net"
	"net/textproto"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/op/go-logging"
)

const (
	cmdQuit = "QUIT"
)

// StatusCode is a thwack status code.
type StatusCode int

const (
	// StatusServiceReady is the status code that is always sent on a new
	// connection to signify that the management interface is ready.
	StatusServiceReady StatusCode = 220

	// StatusOk is the status code returned to signal successful completion
	// of a command.
	StatusOk StatusCode = 250

	// StatusUnknownCommand is the status code returned when a command is
	// unknown.
	StatusUnknownCommand StatusCode = 500

	// StatusSyntaxError is the status code returned when the syntax of a
	// command or it's argument(s) is invalid.
	StatusSyntaxError StatusCode = 501

	// StatusTransactionFailed is the status code returned when the command
	// has failed.
	StatusTransactionFailed StatusCode = 554
)

var statusToString = map[StatusCode]string{
	StatusServiceReady:      "Service ready",
	StatusOk:                "Requested action ok, completed",
	StatusUnknownCommand:    "Syntax error, command unrecognised",
	StatusSyntaxError:       "Syntax error in parameters or arguments",
	StatusTransactionFailed: "Transaction failed",
}

// CommandHandlerFn is a command handler hook function.  Each handler function
// is responsible for fully handling a command and sending a response, and MUST
// NOT return an error unless the connection is to be closed immediately.
type CommandHandlerFn func(*Conn, string) error

// Config is a thwack Server configuration.
type Config struct {
	// Net and Addr specify the network and address of the server instance.
	Net, Addr string

	// ServiceName is the service name to be displayed in the greeting banner.
	ServiceName string

	// LogModule is the module for the Server's Logger.
	LogModule string

	// NewLoggerFn is the function to call to construct per-connection Loggers.
	NewLoggerFn func(string) *logging.Logger
}

// Server is a thwack server instance.
type Server struct {
	sync.WaitGroup

	cfg      *Config
	l        net.Listener
	log      *logging.Logger
	handlers map[string]CommandHandlerFn

	closeAllCh chan interface{}

	connID uint64
}

// Start starts the Server's listener and starts accepting connections.
func (s *Server) Start() error {
	var err error
	s.l, err = net.Listen(s.cfg.Net, s.cfg.Addr)
	if err != nil {
		return err
	}
	s.log.Debugf("Listening on: %v", s.cfg.Addr)

	// Start the listener.
	s.Add(1)
	go func() {
		defer func() {
			s.l.Close()
			s.Done()
		}()
		for {
			conn, err := s.l.Accept()
			if err != nil {
				if e, ok := err.(net.Error); ok && !e.Temporary() {
					s.log.Errorf("Critical accept failure: %v", err)
					return
				}
				s.log.Debugf("Transient accept failure: %v", err)
				continue
			}

			s.log.Debugf("Accepted new connection: %v", conn.RemoteAddr())

			// Allocate the conn state and start the worker.
			c := newConn(s, conn)
			s.Add(1)
			go c.worker()
		}
	}()

	return nil
}

// RegisterCommand sets the handler function for the specified command.
// This MUST NOT be called after the Server has been started with Start().
func (s *Server) RegisterCommand(cmd string, fn CommandHandlerFn) {
	s.handlers[strings.ToUpper(cmd)] = fn
}

func (s *Server) onCommand(c *Conn, l string) error {
	// Clean up the line, and extract the command.
	l = textproto.TrimString(l)
	sp := strings.SplitN(l, " ", 1)
	cmd := strings.ToUpper(sp[0])

	c.Log().Debugf("Received command: %v", cmd)

	// Look up the command in the function table, and call.
	fn, ok := s.handlers[cmd]
	if !ok {
		c.Log().Debugf("Unknown command: %v", cmd)
		return c.WriteReply(StatusUnknownCommand)
	}
	return fn(c, l)
}

// Halt halts the Server.
func (s *Server) Halt() {
	if s.l != nil {
		s.l.Close()
		close(s.closeAllCh)
	}
	s.Wait()
	s.l = nil
}

func cmdQuitImpl(c *Conn, l string) error {
	// Ignore the error writing the reply since we're disconnecting anyway.
	c.WriteReply(StatusOk)
	return fmt.Errorf("peer requested disconnection")
}

// New constructs a new Server, but does not start the listener.
func New(cfg *Config) (*Server, error) {
	s := new(Server)
	s.cfg = cfg
	s.log = cfg.NewLoggerFn(cfg.LogModule)
	s.handlers = make(map[string]CommandHandlerFn)
	s.closeAllCh = make(chan interface{})

	s.RegisterCommand(cmdQuit, cmdQuitImpl)

	return s, nil
}

// Conn is a thwack connection instance.
type Conn struct {
	s     *Server
	c     *textproto.Conn
	log   *logging.Logger
	state interface{}

	id uint64
}

// SetState sets the per-connection state.
func (c *Conn) SetState(state interface{}) {
	c.state = state
}

// State returns the per-connection state.
func (c *Conn) State() interface{} {
	return c.state
}

// Reader returns the underlying textproto.Reader.
func (c *Conn) Reader() *textproto.Reader {
	return &c.c.Reader
}

// Writer returns the underlying textproto.Writer.
func (c *Conn) Writer() *textproto.Writer {
	return &c.c.Writer
}

// Log returns the per-connection logging.Logger.
func (c *Conn) Log() *logging.Logger {
	return c.log
}

// WriteReply is a convenience routine for sending a StatusCode and human
// readable reason to the peer.
func (c *Conn) WriteReply(status StatusCode) error {
	reason, ok := statusToString[status]
	if !ok {
		return fmt.Errorf("BUG: thwack: Unknown status code: %v", status)
	}
	return c.c.Writer.PrintfLine("%v %v", status, reason)
}

func (c *Conn) worker() {
	closedCh := make(chan interface{})
	defer func() {
		c.log.Debugf("Closing")
		c.c.Close()
		c.s.Done()
	}()

	// Send the banner.
	msg := statusToString[StatusServiceReady]
	if c.s.cfg.ServiceName != "" {
		msg = c.s.cfg.ServiceName + " " + msg
	}
	if err := c.c.PrintfLine("%v %v", StatusServiceReady, msg); err != nil {
		c.log.Debugf("Failed to send banner: %v", err)
		return
	}

	go func() {
		defer close(closedCh)
		r := c.Reader()
		for {
			l, err := r.ReadLine()
			if err != nil {
				c.log.Debugf("Failed to receive command: %v", err)
				return
			}

			c.log.Debugf("C->S: '%v'", l)
			if err = c.s.onCommand(c, l); err != nil {
				c.log.Debugf("Failed to process command: %v", err)
				return
			}
		}
	}()

	// Wait till Server teardown, or the command processing go routine
	// returns for whatever reason.
	select {
	case <-c.s.closeAllCh:
		// Server teardown, close the connection and wait for the go
		// routine to return.
		c.c.Close()
		<-closedCh
	case <-closedCh:
	}
}

func newConn(s *Server, conn net.Conn) *Conn {
	c := new(Conn)
	c.s = s
	c.c = textproto.NewConn(conn)
	c.id = atomic.AddUint64(&s.connID, 1)
	c.log = s.cfg.NewLoggerFn(fmt.Sprintf("%s:%d", s.cfg.LogModule, c.id))

	return c
}

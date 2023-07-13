package client2

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"sync"
	"sync/atomic"

	"github.com/charmbracelet/log"
)

// Config is a Server configuration.
type Config struct {
	// Net and Addr specify the network and address of the server instance.
	Net, Addr string

	// LogModule is the module for the Server's Logger.
	LogModule string

	// NewLoggerFn is the function to call to construct per-connection Loggers.
	NewLoggerFn func(string) *log.Logger
}

type Server struct {
	sync.WaitGroup

	cfg      *Config
	log      *log.Logger
	listener net.Listener

	closeAllCh chan interface{}

	connID uint64
}

// NewServer creates a server for listening on the specified socket
// for client requests.
func NewServer(cfg *Config) *Server {
	return &Server{
		cfg:        cfg,
		log:        cfg.NewLoggerFn("server"),
		closeAllCh: make(chan interface{}),
	}
}

// Halt halts the Server.
func (s *Server) Halt() {
	if s.listener != nil {
		s.listener.Close()
		close(s.closeAllCh)
	}
	s.Wait()
	s.listener = nil
}

// Start starts the Server's listener and starts accepting connections.
func (s *Server) Start(ctx context.Context) error {
	var err error
	var lc net.ListenConfig

	s.listener, err = lc.Listen(ctx, s.cfg.Net, s.cfg.Addr)
	if err != nil {
		s.log.Debugf("net.Listen failure: %s", err)
		return err
	}
	s.log.Debugf("Listening on: %v", s.cfg.Addr)

	go func() {
		<-ctx.Done()
		s.log.Info("shutting down")
		s.listener.Close()
	}()

	// Start the listener.
	s.Add(1)
	go func() {
		defer func() {
			s.Done()
		}()
		for {
			conn, err := s.listener.Accept()
			if err != nil {
				s.log.Debugf("Accept failure: %v", err)
				return
			}

			s.log.Debugf("Accepted new connection: %v", conn.RemoteAddr())

			// Allocate the conn state and start the worker.
			s.log.Debug("newConn")
			c := newConn(s, conn)
			s.Add(1)
			go c.worker()
		}
	}()

	return nil
}

type Conn struct {
	s   *Server
	c   net.Conn
	log *log.Logger

	id uint64
}

// Log returns the per-connection log.Logger.
func (c *Conn) Log() *log.Logger {
	return c.log
}

func (c *Conn) onCommand(b []byte) error {
	// XXX FIX ME

	// no op
	return nil
}

func (c *Conn) worker() {
	c.log.Debug("worker")
	closedCh := make(chan interface{})
	defer func() {
		c.log.Debugf("Closing")
		c.c.Close()
		c.s.Done()
	}()

	go func() {
		defer close(closedCh)
		var count int

		for {
			header := make([]byte, 4)
			var err error
			count, err = c.c.Read(header)
			if count != len(header) {
				c.log.Debugf("Received length prefix header of %d bytes instead of 4 bytes", count)
				return
			}

			commandLen := binary.BigEndian.Uint32(header)
			command := make([]byte, commandLen)
			count, err = c.c.Read(command)
			if count != len(command) {
				c.log.Debugf("Received command of %d bytes instead of %d bytes", count, commandLen)
				return
			}
			if err != nil {
				c.log.Debugf("Failed to receive command: %v", err)
				return
			}

			if err = c.onCommand(command); err != nil {
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
	c.c = conn
	c.id = atomic.AddUint64(&s.connID, 1)
	c.log = s.cfg.NewLoggerFn(fmt.Sprintf("%s:%d", s.cfg.LogModule, c.id))

	return c
}

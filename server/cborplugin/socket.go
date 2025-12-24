// socket.go - socket code for cbor plugin system
// Copyright (C) 2021  David Stainton.
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

package cborplugin

import (
	"net"
	"os"
	"time"

	"github.com/fxamacker/cbor/v2"
	"gopkg.in/op/go-logging.v1"

	"github.com/katzenpost/katzenpost/core/worker"
)

// Dialer creates network connections
type Dialer interface {
	Dial(network, address string) (net.Conn, error)
}

// ListenerFactory creates network listeners
type ListenerFactory interface {
	Listen(network, address string) (net.Listener, error)
}

// NetDialer is the default Dialer using net.Dial
type NetDialer struct{}

func (d *NetDialer) Dial(network, address string) (net.Conn, error) {
	return net.Dial(network, address)
}

// NetListenerFactory is the default ListenerFactory using net.Listen
type NetListenerFactory struct{}

func (f *NetListenerFactory) Listen(network, address string) (net.Listener, error) {
	return net.Listen(network, address)
}

// Logger interface for CommandIO logging needs
type Logger interface {
	Debugf(format string, args ...interface{})
	Fatal(args ...interface{})
}

type ServerPlugin interface {
	OnCommand(Command) error
	RegisterConsumer(*Server)

	// GetParameters returns dynamic parameters for PKI advertisement.
	// This is called by the service node when publishing its descriptor.
	// Return nil if no parameters need to be advertised.
	GetParameters() Parameters
}

type ClientPlugin interface {
	OnCommand(Command) error
	RegisterConsumer(*Client)
}

type Command interface {
	Marshal() ([]byte, error)
	Unmarshal(b []byte) error
}

type CommandBuilder interface {
	Build() Command
}

type CommandIO struct {
	worker.Worker

	log      Logger
	conn     net.Conn
	listener net.Listener

	readCh  chan Command
	writeCh chan Command

	commandBuilder  CommandBuilder
	dialer          Dialer
	listenerFactory ListenerFactory

	// retryDelay is the delay between dial retries. Defaults to 1 second.
	// Can be reduced for testing.
	retryDelay time.Duration
}

func NewCommandIO(log *logging.Logger) *CommandIO {
	return &CommandIO{
		log:             log,
		readCh:          make(chan Command),
		writeCh:         make(chan Command),
		dialer:          &NetDialer{},
		listenerFactory: &NetListenerFactory{},
		retryDelay:      time.Second,
	}
}

// NewCommandIOWithDeps creates a CommandIO with injectable dependencies for testing
func NewCommandIOWithDeps(log Logger, dialer Dialer, listenerFactory ListenerFactory) *CommandIO {
	return &CommandIO{
		log:             log,
		readCh:          make(chan Command),
		writeCh:         make(chan Command),
		dialer:          dialer,
		listenerFactory: listenerFactory,
		retryDelay:      time.Second,
	}
}

func (c *CommandIO) Start(initiator bool, socketFile string, commandBuilder CommandBuilder) {
	c.commandBuilder = commandBuilder

	if initiator {

		// it's possible that the plugin has written the socketFile to its stdout
		// but the call to Accept hasn't happened yet, so backoff and wait a bit
		// https://github.com/katzenpost/katzenpost/issues/477
		var err error
		started := false
		for tries := 0; tries < 40; tries++ {
			err = c.dial(socketFile)
			if err != nil {
				time.Sleep(c.retryDelay)
				continue
			} else {
				started = true
				break
			}
		}
		if !started {
			panic(err)
		}
		c.Go(c.reader)
		c.Go(c.writer)
	} else {
		c.log.Debugf("listening to unix domain socket file: %s", socketFile)

		var err error
		c.listener, err = c.listenerFactory.Listen("unix", socketFile)
		if err != nil {
			// 99% of the time the problem is that the old socketFile
			// is still there from previous time we ran, so let's
			// try to remove it and see if that works:
			os.Remove(socketFile)
			c.listener, err = c.listenerFactory.Listen("unix", socketFile)
			if err != nil {
				c.log.Fatal("listen error:", err)
			}
		}
	}
}

func (c *CommandIO) Accept() {
	var err error
	c.conn, err = c.listener.Accept()
	if err != nil {
		c.log.Fatal("accept error:", err)
		return
	}

	c.Go(c.reader)
	c.Go(c.writer)
}

func (c *CommandIO) dial(socketFile string) error {
	c.log.Debugf("dialing unix domain socket file: %s", socketFile)
	var err error
	c.conn, err = c.dialer.Dial("unix", socketFile)
	if err != nil {
		return err
	}

	return nil
}

func (c *CommandIO) ReadChan() chan Command {
	return c.readCh
}

func (c *CommandIO) WriteChan() chan Command {
	return c.writeCh
}

func (c *CommandIO) reader() {
	dec := cbor.NewDecoder(c.conn)
	for {
		cmd := c.commandBuilder.Build()
		err := dec.Decode(cmd)
		if err != nil {
			c.Halt()
			return
		}
		select {
		case <-c.HaltCh():
			return
		case c.readCh <- cmd:
		}
	}
}

func (c *CommandIO) writer() {
	enc := cbor.NewEncoder(c.conn)
	for {
		select {
		case <-c.HaltCh():
			return
		case cmd := <-c.writeCh:
			err := enc.Encode(cmd)
			if err != nil {
				c.Halt()
				return
			}
		}
	}
}

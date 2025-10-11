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
	"github.com/fxamacker/cbor/v2"
	"gopkg.in/op/go-logging.v1"
	"net"
	"os"
	"time"

	"github.com/katzenpost/katzenpost/core/worker"
)

type ServerPlugin interface {
	OnCommand(Command) error
	RegisterConsumer(*Server)
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

	log      *logging.Logger
	conn     net.Conn
	listener net.Listener

	readCh  chan Command
	writeCh chan Command

	commandBuilder CommandBuilder
}

func NewCommandIO(log *logging.Logger) *CommandIO {
	return &CommandIO{
		log:     log,
		readCh:  make(chan Command),
		writeCh: make(chan Command),
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
				time.Sleep(time.Second)
				continue
			} else {
				started = true
				break
			}
		}
		if started != true {
			panic(err)
		}
		c.Go(c.reader)
		c.Go(c.writer)
	} else {
		c.log.Debugf("listening to unix domain socket file: %s", socketFile)

		var err error
		c.listener, err = net.Listen("unix", socketFile)
		if err != nil {
			// 99% of the time the problem is that the old socketFile
			// is still there from previous time we ran, so let's
			// try to remove it and see if that works:
			os.Remove(socketFile)
			c.listener, err = net.Listen("unix", socketFile)
			c.log.Fatal("listen error:", err)
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
	c.conn, err = net.Dial("unix", socketFile)
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

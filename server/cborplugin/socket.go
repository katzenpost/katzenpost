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

	"github.com/fxamacker/cbor/v2"
	"gopkg.in/op/go-logging.v1"

	"github.com/katzenpost/katzenpost/core/worker"
)

type ServerPlugin interface {
	OnCommand(Command) (Command, error)
	RegisterConsumer(*Server)
}

type ClientPlugin interface {
	OnCommand(interface{}) (Command, error)
	RegisterConsumer(*Client)
}

type Command interface {
	Marshal() ([]byte, error)
	Unmarshal(b []byte) error
}

type CommandIO struct {
	worker.Worker

	log      *logging.Logger
	conn     net.Conn
	listener net.Listener

	readCh  chan Command
	writeCh chan Command
}

func NewCommandIO(log *logging.Logger) *CommandIO {
	return &CommandIO{
		log:     log,
		readCh:  make(chan Command),
		writeCh: make(chan Command),
	}
}

func (c *CommandIO) Start(initiator bool, socketFile string) {

	if initiator {
		err := c.dial(socketFile)
		if err != nil {
			panic(err)
		}
		c.Go(c.reader)
		c.Go(c.writer)
	} else {
		c.log.Debugf("listening to unix domain socket file: %s", socketFile)
		var err error
		c.listener, err = net.Listen("unix", socketFile)
		if err != nil {
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
	// register different types with decoder and create a decoder
	dm, err := cbor.DecOptions{}.DecModeWithTags(TagSet)
	if err != nil {
		panic(err)
	}
	dec := dm.NewDecoder(c.conn)

	for {
		var cmd Command
		err := dec.Decode(&cmd)
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
	em, err := cbor.EncOptions{}.EncModeWithTags(TagSet)
	if err != nil {
		panic(err)
	}
	enc := em.NewEncoder(c.conn)
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

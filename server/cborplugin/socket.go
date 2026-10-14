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
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/fxamacker/cbor/v2"
	"gopkg.in/op/go-logging.v1"

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

	maxCommandLength int

	failOnce sync.Once
	err      error
}

var errCommandTooLong = errors.New("cborplugin: command exceeds the length bound")

func NewCommandIO(log *logging.Logger) *CommandIO {
	return &CommandIO{
		log:     log,
		readCh:  make(chan Command),
		writeCh: make(chan Command),
	}
}

// Start connects (initiator) or listens (!initiator) on socketFile. For the
// initiator case, abortCh lets a caller cut the dial-retry loop short as
// soon as it knows the plugin process has already died, rather than
// exhausting the full retry budget against a socket that will never accept.
// abortCh may be nil, in which case the loop always runs its full budget.
func (c *CommandIO) Start(initiator bool, socketFile string, commandBuilder CommandBuilder, abortCh <-chan interface{}) error {
	c.commandBuilder = commandBuilder

	if initiator {

		// it's possible that the plugin has written the socketFile to its stdout
		// but the call to Accept hasn't happened yet, so backoff and wait a bit
		// https://github.com/katzenpost/katzenpost/issues/477
		const maxTries = 40
		var err error
		started := false
		tries := 0
		for ; tries < maxTries; tries++ {
			err = c.dial(socketFile)
			if err == nil {
				started = true
				break
			}
			select {
			case <-abortCh:
				return fmt.Errorf("gave up dialing %q after %d/%d tries, plugin process exited: %w", socketFile, tries+1, maxTries, err)
			case <-time.After(time.Second):
			}
		}
		if !started {
			return fmt.Errorf("gave up dialing %q after %d tries: %w", socketFile, maxTries, err)
		}
		c.serve()
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
			if err != nil {
				c.log.Fatal("listen error:", err)
			}
		}
	}
	return nil
}

func (c *CommandIO) Accept() {
	var err error
	c.conn, err = c.listener.Accept()
	if err != nil {
		c.log.Fatal("accept error:", err)
		return
	}

	c.serve()
}

func (c *CommandIO) serve() {
	c.Go(c.reader)
	c.Go(c.writer)
	c.Go(func() {
		<-c.HaltCh()
		c.conn.Close()
	})
}

func (c *CommandIO) fail(err error) {
	c.failOnce.Do(func() {
		c.err = err
		c.Stop()
	})
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
	var src io.Reader = c.conn
	limit := &io.LimitedReader{R: c.conn, N: int64(c.maxCommandLength)}
	if c.maxCommandLength > 0 {
		src = limit
	}
	dec := cbor.NewDecoder(src)
	for {
		cmd := c.commandBuilder.Build()
		err := dec.Decode(cmd)
		if err != nil {
			if src == limit && limit.N == 0 {
				err = errCommandTooLong
			}
			c.fail(err)
			return
		}
		limit.N = int64(c.maxCommandLength)
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
				c.fail(err)
				return
			}
		}
	}
}

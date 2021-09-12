// incoming_conn.go - katzenpost client plugins server incoming connection
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

// Package cborplugin is a plugin system allowing mix network services
// to be added in any language. It communicates queries and responses to and from
// the mix server using CBOR over HTTP over UNIX domain socket. Beyond that,
// a client supplied SURB is used to route the response back to the client
// as described in our Kaetzchen specification document:
//
// https://github.com/katzenpost/docs/blob/master/specs/kaetzchen.rst
//
package cborplugin

import (
	"container/list"
	"encoding/binary"
	"io"
	"net"

	"github.com/fxamacker/cbor/v2"
	"gopkg.in/op/go-logging.v1"

	"github.com/katzenpost/client/constants"
	"github.com/katzenpost/core/crypto/rand"
	"github.com/katzenpost/core/log"
)

type incomingConn struct {
	log  *logging.Logger
	conn net.Conn
	e    *list.Element

	server  *Server
	session Session

	commandBuilder CommandBuilder

	closeConnectionCh chan bool
}

func newIncomingConn(logBackend *log.Backend, s *Server, conn net.Conn, session Session) *incomingConn {
	c := &incomingConn{
		server:            s,
		conn:              conn,
		session:           session,
		closeConnectionCh: make(chan bool),

		commandBuilder: new(ControlCommandBuilder),
	}
	c.log = logBackend.GetLogger("incoming conn")

	c.log.Debugf("New incoming connection: %v", conn.RemoteAddr())

	// Note: Unlike most other things, this does not spawn the worker here,
	// because the worker needs to be spawned after the struct is added to
	// the connection list.

	return c
}

func (c *incomingConn) Close() {
	c.closeConnectionCh <- true
}

func (c *incomingConn) worker() {
	defer func() {
		c.log.Debug("closing")
		c.conn.Close()
		c.server.onClosedConn(c)
	}()

	for {
		select {
		case <-c.closeConnectionCh:
			return
		default:
		}

		cmd := c.commandBuilder.Build()
		err := readCommand(c.conn, cmd)
		if err != nil {
			c.log.Error(err.Error())
		}
		c.processCommand(cmd)
	}
}

func (c *incomingConn) WriteCommand(cmd Command) {
	err := writeCommand(c.conn, cmd)
	if err != nil {
		c.log.Error(err.Error())
	}
}

func (c *incomingConn) processCommand(rawCommand Command) {
	command, ok := rawCommand.(*ControlCommand)
	if !ok {
		c.log.Error("invalid command")
		return
	}
	if command.SendMessage != nil && command.CreateRemoteSpool != nil {
		c.log.Error("only one command at a time")
		return
	}
	if command.SendMessage == nil && command.CreateRemoteSpool == nil {
		c.log.Error("at least one command is required")
		return
	}

	if command.SendMessage != nil {
		id := [constants.MessageIDLength]byte{}
		_, err := io.ReadFull(rand.Reader, id[:])
		if err != nil {
			c.log.Error(err.Error())
		}

		err = c.session.SendMessage(command.SendMessage.Recipient, command.SendMessage.Provider, command.SendMessage.Payload, id)
		if err != nil {
			c.log.Error(err.Error())
		}

		c.server.ReplyToSentMessage(&id, c)

		return
	}

	/*
		type CreateRemoteSpool struct {
			Recipient string
			Provider  string
			SpoolID   []byte
		}
	*/
	if command.CreateRemoteSpool != nil {
		panic("CreateRemoteSpool not yet implemented")
		return
	}
}

func readCommand(conn net.Conn, command Command) error {
	rawLen := make([]byte, 2)
	_, err := conn.Read(rawLen)
	if err != nil {
		return err
	}
	commandLen := binary.BigEndian.Uint16(rawLen)

	rawCommand := make([]byte, commandLen)
	_, err = conn.Read(rawCommand)
	if err != nil {
		return err
	}
	err = cbor.Unmarshal(rawCommand, command)
	if err != nil {
		return err
	}

	return nil
}

func writeCommand(conn net.Conn, command Command) error {
	serialized, err := cbor.Marshal(command)
	if err != nil {
		return err
	}

	output := make([]byte, 0, len(serialized)+2)
	tmp := make([]byte, 2)
	binary.BigEndian.PutUint16(tmp, uint16(len(serialized)))
	output = append(output, tmp...)
	output = append(output, serialized...)
	_, err = conn.Write(output)
	if err != nil {
		return err
	}

	return nil
}

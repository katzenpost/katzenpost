// server.go - server of cbor plugin system
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
	//"net"

	"gopkg.in/op/go-logging.v1"

	"github.com/katzenpost/katzenpost/core/worker"
)

// Server is used to construct plugins, which are programs which
// listen on a unix domain socket for connections from the Provider/mix server.
type Server struct {
	worker.Worker

	socket         *CommandIO
	log            *logging.Logger
	//conn           net.Conn
	socketFile     string
	plugin         ServerPlugin
	commandBuilder CommandBuilder
}

func NewServer(log *logging.Logger, socketFile string, commandBuilder CommandBuilder, plugin ServerPlugin) *Server {
	s := &Server{
		log:            log,
		socketFile:     socketFile,
		plugin:         plugin,
		commandBuilder: commandBuilder,
		socket:         NewCommandIO(log),
	}
	s.plugin.RegisterConsumer(s)
	s.socket.Start(false, s.socketFile, s.commandBuilder)
	return s
}

func (s *Server) Accept() {
	s.socket.Accept()
	s.Go(s.worker)
}

func (s *Server) worker() {
	for {
		select {
		case <-s.HaltCh():
			return
		case cmd := <-s.socket.ReadChan():
			reply, err := s.plugin.OnCommand(cmd)
			if err != nil {
				s.log.Debugf("plugin returned err: %s", err)
			}
			select {
			case <-s.HaltCh():
				return
			case s.socket.WriteChan() <- reply:
			}
		}
	}
}

func (s *Server) Write(cmd Command) {
	select {
	case <-s.HaltCh():
		return
	case s.socket.WriteChan() <- cmd:
	}
}

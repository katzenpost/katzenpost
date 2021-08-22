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
	"net"

	"gopkg.in/op/go-logging.v1"

	"github.com/katzenpost/core/worker"
)

type Server struct {
	worker.Worker

	log        *logging.Logger
	conn       net.Conn
	socketFile string
	plugin     Plugin
}

func NewServer(log *logging.Logger, socketFile string, plugin Plugin) *Server {
	s := &Server{
		log:        log,
		socketFile: socketFile,
		plugin:     plugin,
	}
	s.Go(s.worker)
	return s
}

func (s *Server) worker() {
	l, err := net.Listen("unix", s.socketFile)
	if err != nil {
		s.log.Fatal("listen error:", err)
	}
	defer l.Close()

	for {
		select {
		case <-s.HaltCh():
			return
		default:
		}
		s.conn, err = l.Accept()
		if err != nil {
			s.log.Fatal("accept error:", err)
			return
		}

		err := s.serviceConnection()
		if err != nil {
			s.log.Fatal("accept error:", err)
			return
		}
	}
}

func (s *Server) serviceConnection() error {
	for {
		select {
		case <-s.HaltCh():
			return nil
		default:
		}

		var request Command
		err := readCommand(s.conn, request)
		if err != nil {
			return err
		}

		response, err := s.plugin.OnRequest(request)
		if err != nil {
			return err
		}

		err = writeCommand(s.conn, response)
		if err != nil {
			return err
		}
	}

	return nil
}

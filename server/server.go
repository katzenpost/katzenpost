// server.go - Reunion server.
// Copyright (C) 2019  David Stainton.
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

// Package server provides the Reunion protocol server.
package server

import (
	"errors"

	"github.com/katzenpost/reunion/commands"
)

// Server is a reunion server.
type Server struct {
	state *ReunionState
}

// NewServer returns a new Server with a new ReunionState.
func NewServer() *Server {
	return &Server{
		state: NewReunionState(),
	}
}

// ProcessQuery processes the given query command and returns a response command or an error.
func (s *Server) ProcessQuery(command commands.Command, haltCh chan interface{}) (commands.Command, error) {
	var response commands.Command
	switch cmd := command.(type) {
	case *commands.FetchState:
		messages, ok := s.state.messageMap.Load(cmd.T1Hash)
		if !ok {
			return nil, errors.New("invalid message map value")
		}
		messageList, ok := messages.(*LockedList)
		if !ok {
			return nil, errors.New("invalid message list")
		}
		t2t3messages, err := messageList.Serializable()
		if err != nil {
			return nil, err
		}
		t1Map, err := s.state.SerializableT1Map()
		if err != nil {
			return nil, err
		}
		requested := &RequestedReunionState{
			T1Map:    t1Map,
			Messages: t2t3messages,
		}
		serialized, err := requested.Marshal()
		if err != nil {
			return nil, err
		}
		response = &commands.StateResponse{
			ErrorCode:          commands.ResponseStatusOK,
			Truncated:          false,
			LeftOverChunksHint: 0,
			Payload:            serialized,
		}
	case *commands.SendT1:
		err := s.state.AppendMessage(cmd)
		if err != nil {
			return nil, err
		}
		response = &commands.MessageResponse{
			ErrorCode: commands.ResponseStatusOK,
		}
	case *commands.SendT2:
		err := s.state.AppendMessage(cmd)
		if err != nil {
			return nil, err
		}
		response = &commands.MessageResponse{
			ErrorCode: commands.ResponseStatusOK,
		}
	case *commands.SendT3:
		err := s.state.AppendMessage(cmd)
		if err != nil {
			return nil, err
		}
		response = &commands.MessageResponse{
			ErrorCode: commands.ResponseStatusOK,
		}
	default:
		return nil, errors.New("invalid query command received")
	}
	return response, nil
}

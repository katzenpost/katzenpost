// server.go - Reunion server.
// Copyright (C) 2019, 2020  David Stainton.
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
	"fmt"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/core/worker"
	"github.com/katzenpost/katzenpost/reunion/commands"
	"github.com/katzenpost/katzenpost/reunion/epochtime"
	"github.com/katzenpost/katzenpost/server/cborplugin"
	"gopkg.in/op/go-logging.v1"
)

// Tune me.
const (
	writeBackInterval = 10 * time.Second
	epochGracePeriod  = 3 * time.Minute
)

// Server is a reunion server.
type Server struct {
	sync.RWMutex
	worker.Worker

	stateFilePath string
	states        *ReunionStates
	nDirtyEntries uint64
	epochClock    epochtime.EpochClock
	log           *logging.Logger
	logBackend    *log.Backend
	write         func(cborplugin.Command)
}

// NewServerFromStatefile loads the state from a file.
func NewServerFromStatefile(epochClock epochtime.EpochClock, stateFilePath, logPath, logLevel string) (*Server, error) {
	logBackend, err := log.New(logPath, logLevel, false)
	if err != nil {
		return nil, err
	}
	s := &Server{
		stateFilePath: stateFilePath,
		states:        NewReunionStates(),
		nDirtyEntries: 0,
		epochClock:    epochClock,
		logBackend:    logBackend,
		log:           logBackend.GetLogger("reunion_server_core"),
	}
	err = s.states.LoadFromFile(stateFilePath)
	if err != nil {
		return nil, err
	}
	s.states.MaybeAddEpochs(s.epochClock)
	s.states.GarbageCollectOldEpochs(epochClock)
	s.Go(s.worker)
	return s, nil
}

// NewServer returns a new Server with a new ReunionState.
func NewServer(epochClock epochtime.EpochClock, stateFilePath, logPath, logLevel string) (*Server, error) {
	logBackend, err := log.New(logPath, logLevel, false)
	if err != nil {
		return nil, err
	}
	s := &Server{
		stateFilePath: stateFilePath,
		states:        NewReunionStates(),
		nDirtyEntries: 0,
		epochClock:    epochClock,
		logBackend:    logBackend,
		log:           logBackend.GetLogger("reunion_server_core"),
	}
	s.states.MaybeAddEpochs(s.epochClock)
	s.Go(s.worker)
	return s, nil
}

// GetNewLogger returns a logger for the given subsystem name.
func (s *Server) GetNewLogger(name string) *logging.Logger {
	return s.logBackend.GetLogger(name)
}

func (s *Server) incrementDirtyEntryCount() {
	atomic.AddUint64(&s.nDirtyEntries, 1)
}

func (s *Server) fetchState(fetchCmd *commands.FetchState) (*commands.StateResponse, error) {
	state, err := s.states.GetStateFromEpoch(fetchCmd.Epoch)
	if err != nil {
		return nil, err
	}
	messages, ok := state.messageMap.Load(fetchCmd.T1Hash)
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
	t1Map, err := state.SerializableT1Map()
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
	response := &commands.StateResponse{
		ErrorCode:          commands.ResponseStatusOK,
		Truncated:          false,
		LeftOverChunksHint: 0,
		Payload:            serialized,
	}
	return response, nil
}

func (s *Server) sendT1(sendT1 *commands.SendT1) (*commands.MessageResponse, error) {
	state, err := s.states.GetStateFromEpoch(sendT1.Epoch)
	if err != nil {
		return nil, err
	}
	err = state.AppendMessage(sendT1)
	if err != nil {
		return nil, err
	}
	s.incrementDirtyEntryCount()
	response := &commands.MessageResponse{
		ErrorCode: commands.ResponseStatusOK,
	}
	return response, nil
}

func (s *Server) sendT2(sendT2 *commands.SendT2) (*commands.MessageResponse, error) {
	state, err := s.states.GetStateFromEpoch(sendT2.Epoch)
	if err != nil {
		return nil, err
	}
	err = state.AppendMessage(sendT2)
	if err != nil {
		return nil, err
	}
	s.incrementDirtyEntryCount()
	response := &commands.MessageResponse{
		ErrorCode: commands.ResponseStatusOK,
	}
	return response, nil
}

func (s *Server) sendT3(sendT3 *commands.SendT3) (*commands.MessageResponse, error) {
	state, err := s.states.GetStateFromEpoch(sendT3.Epoch)
	if err != nil {
		return nil, err
	}
	err = state.AppendMessage(sendT3)
	if err != nil {
		return nil, err
	}
	s.incrementDirtyEntryCount()
	response := &commands.MessageResponse{
		ErrorCode: commands.ResponseStatusOK,
	}
	return response, nil
}

// RegisterConsumers implements cborplugin.PluginClient
func (s *Server) RegisterConsumer(svr *cborplugin.Server) {
	s.write = svr.Write
}

// OnCommand implemenets cborplugin.PluginClient
func (s *Server) OnCommand(cmd cborplugin.Command) error {
	switch r := cmd.(type) {
	case *cborplugin.Request:
		cmd, err := commands.FromBytes(r.Payload)
		var replyCmd commands.Command
		if err != nil {
			s.log.Errorf("invalid Reunion query command found in request Payload len %d: %s", len(r.Payload), err.Error())
			return err
		}
		s.Go(func() {
			replyCmd, err = s.ProcessQuery(cmd)
			if err != nil {
				s.log.Errorf("reunion server invalid reply command: %s", err.Error())
				// XXX: this is also triggered by an expired epoch... and does not return error to client
				replyCmd = &commands.MessageResponse{ErrorCode: commands.ResponseInvalidCommand}
			}

			rawReply := replyCmd.ToBytes()
			s.write(&cborplugin.Response{ID: r.ID, SURB: r.SURB, Payload: rawReply})
		})
	default:
		s.log.Errorf("OnCommand called with unknown Command type")
		return errors.New("Invalid Command type")
	}
	return nil
}

// ProcessQuery processes the given query command and returns a response command or an error.
func (s *Server) ProcessQuery(command commands.Command) (commands.Command, error) {
	var err error
	var response commands.Command
	switch cmd := command.(type) {
	case *commands.FetchState:
		s.log.Debug("fetch state")
		response, err = s.fetchState(cmd)
		if err != nil {
			return nil, err
		}
	case *commands.SendT1:
		s.log.Debug("send t1")
		response, err = s.sendT1(cmd)
		if err != nil {
			return nil, err
		}
	case *commands.SendT2:
		s.log.Debug("send t2")
		response, err = s.sendT2(cmd)
		if err != nil {
			return nil, err
		}
	case *commands.SendT3:
		s.log.Debug("send t3")
		response, err = s.sendT3(cmd)
		if err != nil {
			return nil, err
		}
	default:
		s.log.Debug("Reunion server ProcessQuery received invalid query command")
		return nil, errors.New("Reunion server ProcessQuery received invalid query command")
	}
	return response, nil
}

func (s *Server) doFlush() error {
	return s.states.AtomicWriteToFile(s.stateFilePath)
}

func (s *Server) maybeFlush() {
	nEntries := atomic.LoadUint64(&s.nDirtyEntries)
	if nEntries == 0 {
		return
	}
	err := s.doFlush()
	if err != nil {
		// FIXME(david): doFlush fails on windows and thus crashes here.
		// For now let's just print a warning to stderr and the log.
		//panic("flush to disk failure, aborting...")

		fmt.Fprintf(os.Stderr, "WARNING: doFlush failed: %s\n", err)
		s.log.Warningf("WARNING: doFlush failed: %s", err)
	}
	atomic.StoreUint64(&s.nDirtyEntries, 0)
}

func (s *Server) worker() {
	defer s.doFlush()

	flushTicker := time.NewTicker(writeBackInterval)
	defer flushTicker.Stop()

	gcTicker := time.NewTicker(s.epochClock.Period() / 2)
	defer gcTicker.Stop()

	newEpochTicker := time.NewTicker(s.epochClock.Period() / 8)
	defer flushTicker.Stop()

	for {
		select {
		case <-s.HaltCh():
			return
		case <-flushTicker.C:
			s.maybeFlush()
			continue
		case <-gcTicker.C:
			s.states.GarbageCollectOldEpochs(s.epochClock)
			continue
		case <-newEpochTicker.C:
			s.states.MaybeAddEpochs(s.epochClock)
			continue
		}
	}
}

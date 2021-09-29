// server.go - katzenpost client plugins server
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
	"net"
	"sync"
	"time"

	"gopkg.in/op/go-logging.v1"

	"github.com/katzenpost/katzenpost/client/constants"
	"github.com/katzenpost/katzenpost/client/events"
	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/core/worker"
)

type Session interface {
	SendMessage(recipient, provider string, message []byte, ID [constants.MessageIDLength]byte) error
}

type SentMessage struct {
	Time               time.Time
	IncomingConnection *incomingConn
}

type Server struct {
	sync.Mutex
	worker.Worker

	log        *logging.Logger
	logBackend *log.Backend

	eventsInCh  chan events.Event
	replyRoutes *sync.Map // message ID -> *SentMessage

	listener net.Listener
	conns    *list.List

	closeAllWg sync.WaitGroup
	closeAllCh chan interface{}

	connectionStatusLock *sync.RWMutex
	isConnected          bool

	session Session
}

func NewServer(logBackend *log.Backend, socketFile string, session Session) *Server {
	s := &Server{
		logBackend:           logBackend,
		log:                  logBackend.GetLogger("server"),
		session:              session,
		eventsInCh:           make(chan events.Event),
		replyRoutes:          new(sync.Map),
		closeAllCh:           make(chan interface{}),
		connectionStatusLock: new(sync.RWMutex),
	}

	s.log.Debugf("listening to unix domain socket file: %s", socketFile)
	var err error
	s.listener, err = net.Listen("unix", socketFile)
	if err != nil {
		s.log.Fatal("listen error:", err)
	}
	s.Go(s.eventWorker)
	s.Go(s.connectionWorker)

	return s
}

func (s *Server) Halt() {
	s.listener.Close()
	s.Worker.Halt()
	close(s.closeAllCh)
	s.closeAllWg.Wait()
}

func (s *Server) EventSink() chan events.Event {
	return s.eventsInCh
}

func (s *Server) eventWorker() {
	for {
		select {
		case <-s.HaltCh():
			return
		case event := <-s.eventsInCh:
			s.processEvent(event)
		}
	}
}

func (s *Server) processEvent(event events.Event) {
	switch v := event.(type) {
	case *events.ConnectionStatusEvent:
		s.sendEvent(Event{
			ConnectionStatusEvent: v,
		})
	case *events.MessageReplyEvent:
		rawSentMessage, ok := s.replyRoutes.Load(v.MessageID)
		if !ok {
			s.log.Error("no reply route found for message ID")
			return
		}
		sentMessage, ok := rawSentMessage.(*SentMessage)
		if !ok {
			s.log.Error("invalid reply route")
			return
		}

		event := Event{
			MessageReplyEvent: v,
		}
		sentMessage.IncomingConnection.WriteEvent(event)

		s.replyRoutes.Delete(v.MessageID)
	case *events.MessageSentEvent:
		s.sendEvent(Event{
			MessageSentEvent: v,
		})
	case *events.MessageIDGarbageCollected:
	case *events.NewDocumentEvent:
		s.sendEvent(Event{
			NewDocumentEvent: v,
		})
	default:
		s.log.Error("Plugins: received invalid event type")
		return
	}
}

func (s *Server) SetConnectionStatus(isConnected bool) {
	s.connectionStatusLock.Lock()
	defer s.connectionStatusLock.Unlock()

	s.isConnected = isConnected
}

func (s *Server) ConnectionStatus() bool {
	s.connectionStatusLock.RLock()
	defer s.connectionStatusLock.RUnlock()

	return s.isConnected
}

func (s *Server) connectionWorker() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			if e, ok := err.(net.Error); ok && !e.Temporary() {
				s.log.Errorf("Critical accept failure: %v", err)
				return
			}
			continue
		}

		s.log.Debugf("Accepted new connection: %v", conn.RemoteAddr())

		s.onNewConn(conn)
	}
}

func (s *Server) onNewConn(conn net.Conn) {
	c := newIncomingConn(s.logBackend, s, conn, s.session)

	s.closeAllWg.Add(1)
	s.Lock()
	defer func() {
		s.Unlock()
		go c.worker()
	}()
	c.e = s.conns.PushFront(c)
}

func (s *Server) onClosedConn(conn *incomingConn) {
	s.Lock()
	defer func() {
		s.Unlock()
		s.closeAllWg.Done()
	}()
	s.conns.Remove(conn.e)
}

func (s *Server) ReplyToSentMessage(id *[constants.MessageIDLength]byte, incomingConn *incomingConn) {
	sentMessage := SentMessage{
		Time:               time.Now(),
		IncomingConnection: incomingConn,
	}
	s.replyRoutes.Store(id, &sentMessage)
}

func (s *Server) sendEvent(event Event) {
	s.Lock()
	defer s.Unlock()

	for e := s.conns.Front(); e != nil; e = e.Next() {
		conn, ok := e.Value.(*incomingConn)
		if !ok {
			panic("wtf")
		}
		conn.WriteEvent(event)
	}
}

// server.go - stream socket service using cbor plugin system
// Copyright (C) 2023  Masala
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

package server

import (
	"bytes"
	"context"
	"errors"
	"gopkg.in/op/go-logging.v1"
	"io"
	"net/url"
	"sync"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/katzenpost/katzenpost/client"
	"github.com/katzenpost/katzenpost/client/config"
	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/worker"
	"github.com/katzenpost/katzenpost/server/cborplugin"
	"github.com/katzenpost/katzenpost/stream"
)

var (
	// clients must start reading from their streams
	// or else the worker will abandon the stream
	connectDeadine = time.Minute
	errShutdown    = errors.New("Halted")
)

// XXX: observation
// creating 2 requests and crossing the streams
// will cause the worker to generate decoy traffic
// on the map server
// but can also be a DoS - should the SocketServer
// use a bloom filter to ensure that stream addresses
// are single use ?

// SockatzServer is a kaetzchen responder that proxies
// a TCP connection to the host specified in a Stream
type Sockatz struct {
	cfg *config.Config
	worker.Worker
	log         *logging.Logger
	maxWorkers  int
	requests    chan *SockatzRequest
	doneRequest chan struct{}
}

// NewSockatz instantiates the Sockatz Kaetzchen responder
func NewSockatz(cfgFile string, log *logging.Logger, maxWorkers int) (*Sockatz, error) {
	cfg, err := config.LoadFile(cfgFile)
	if err != nil {
		return nil, err
	}
	s := &Sockatz{cfg: cfg, maxWorkers: maxWorkers, log: log,
		requests:    make(chan *SockatzRequest, maxWorkers),
		doneRequest: make(chan struct{}, maxWorkers),
	}
	log.Debug("starting worker")
	s.Go(s.worker)
	log.Debug("started worker")
	return s, nil
}

// SockatzRequest is the type encapsulating an Endpoint to connect and the
// Address of a Stream to proxy to
type SockatzRequest struct {
	Endpoint *url.URL
	Stream string
}

// Marshal implements cborplugin.Command
func (s *SockatzRequest) Marshal() ([]byte, error) {
	return cbor.Marshal(s)
}

// Unmarshal implements cborplugin.Command
func (s *SockatzRequest) Unmarshal(b []byte) error {
	return cbor.Unmarshal(b, s)
}

// SockatzStatus is the response type from the Sockatz Server
type SockatzStatus uint8

const (
	StatusRequestStarted SockatzStatus = iota
	StatusRequestEnqueued
	StatusRequestRejected
)

// SockatzResponse is the type encapsulating the Sockatz Server response
type SockatzResponse struct {
	Status SockatzStatus
}

// Marshal implements cborplugin.Command
func (s *SockatzResponse) Marshal() ([]byte, error) {
	return cbor.Marshal(s)
}

// Unarshal implements cborplugin.Command
func (s *SockatzResponse) Unmarshal(b []byte) error {
	return cbor.Unmarshal(b, s)
}

// getSession waits until pki.Document is available and returns a *client.Session
func (s *Sockatz) getSession() (*client.Session, error) {
	var err error
	cc, err := client.New(s.cfg)
	if err != nil {
		return nil, err
	}

	var session *client.Session
	for session == nil {
		session, err = cc.NewTOFUSession()
		switch err {
		case nil:
		case pki.ErrNoDocument:
			_, _, till := epochtime.Now()
			select {
			case <-time.After(till):
			case <-s.HaltCh():
				return nil, errors.New("Halted")
			}
		default:
			s.log.Errorf("Failed to get session:", err)
		}
	}
	session.WaitForDocument()
	return session, nil
}

func (s *Sockatz) worker() {
	s.log.Notice("Started Sockatz worker")
	defer s.log.Notice("Stopping Sockatz worker")

	// get a session
	session, err := s.getSession()
	if err != nil {
		s.log.Errorf("Failed to get client connection: %s", err)
		return
	}
	s.log.Notice("Got session")
	nRequests := 0
	for {
		s.log.Notice("worker loop")
		select {
		case <-s.HaltCh():
			return
		case cborReq := <-s.requests:
			if nRequests < s.maxWorkers {
				// start a worker routine to process the request
				nRequests++
				s.Go(func() {
					s.handleRequest(session, cborReq)
				})
			}
		case <-s.doneRequest:
			nRequests--
		}
	}
}

// handleRequest starts a stream worker and proxies the endpoint to the stream until either EOF
func (s *Sockatz) handleRequest(session *client.Session, request *SockatzRequest) error {

	// start stream worker for the reply
	s.log.Notice("launching stream socket worker")

	s.log.Debugf("dialing stream address: %x", request.Stream)
	if session == nil {
		panic("wtf")
	}
	reply, err := stream.DialDuplex(session, "", request.Stream)
	s.log.Debugf("after DialDuplex")
	if err != nil {
		s.log.Debugf("dialing failed: %s", err)
		return err
	}

	// dial the remote host (using our local proxy config if specified)
	pCfg := s.cfg.UpstreamProxyConfig()
	pCfg.Type = "socks5"
	pCfg.Network = "tcp"
	pCfg.Address = "10.42.42.42:9050"
	ctx := context.Background() //XXX with default timeout / teardown
	s.log.Debugf("dialing endpoint address: %s", request.Endpoint.String())
	endpoint, err := pCfg.ToDialContext("")(ctx, "tcp", request.Endpoint.String())
	if err != nil {
		s.log.Error("Caught %s", err)
		return err
	}
	defer func() {
		select {
		case s.doneRequest <- struct{}{}:
		default:
		}
	}()
	if err = copyLoop(reply, endpoint); err != nil {
		s.log.Error("Caught %s", err)
		return err
	}
	return nil
}

func copyLoop(a io.ReadWriteCloser, b io.ReadWriteCloser) error {
	// Note: b is always the Stream.  a is the SOCKS/ORPort connection.
	errChan := make(chan error, 2)

	var wg sync.WaitGroup
	wg.Add(2)

	go func() {
		defer wg.Done()
		// XXX: use a LimitedReader and update some flow stats
		_, err := io.Copy(b, a)
		if err != nil {
			errChan <- err
		}
		// copying from stream to endpoint failed
		a.Close()
		b.Close()

	}()
	go func() {
		defer wg.Done()
		// XXX: use a LimitedReader and update some flow stats
		_, err := io.Copy(a, b)
		if err != nil {
			errChan <- err
		}
		// copying from endpoint to stream
		b.Close()
		a.Close()
	}()

	// Wait for both upstream and downstream to close.  Since one side
	// terminating closes the other, the second error in the channel will be
	// something like EINVAL (though io.Copy() will swallow EOF), so only the
	// first error is returned.
	wg.Wait()
	if len(errChan) > 0 {
		return <-errChan
	}

	return nil
}

// OnCommand implements cborplugin.ServicePlugin OnCommand
func (s *Sockatz) OnCommand(cmd cborplugin.Command) (cborplugin.Command, error) {
	switch r := cmd.(type) {
	case *cborplugin.Request:
		if !r.HasSURB {
			s.log.Notice("Got request with no SURB, no reply to send")
		}

		req := &SockatzRequest{}
		dec := cbor.NewDecoder(bytes.NewReader(r.Payload))
		err := dec.Decode(req)
		if err != nil {
			return nil, err
		}

		resp := &SockatzResponse{}

		// send the request to worker to dispatch or drop
		select {
		case <-s.HaltCh():
			return nil, errShutdown
		case s.requests <- req:
			// request succesfully dispatched
			resp.Status = StatusRequestStarted
		default: //case <-time.After(spawnDeadline):
			// workers are too busy (maxWorkers), reject this request
			// XXX: or enqueue the request and reply with a RequestEnqueued
			// so the client knows not to expect an immediate response
			resp.Status = StatusRequestRejected
		}
		rawResp, err := resp.Marshal()
		return &cborplugin.Response{Payload: rawResp}, nil
	default:
		s.log.Errorf("OnCommand called with unknown Command type")
		return nil, errors.New("Invalid Command type")
	}
}

func (s *Sockatz) RegisterConsumer(svr *cborplugin.Server) {
	s.log.Debugf("RegisterConsumer called")
}

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
	"errors"
	"gopkg.in/op/go-logging.v1"
	"github.com/katzenpost/katzenpost/core/log"
	"fmt"
	"net"
	"net/url"
	"sync"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/katzenpost/katzenpost/client/config"
	"github.com/katzenpost/katzenpost/core/worker"
	"github.com/katzenpost/katzenpost/server/cborplugin"
	"github.com/katzenpost/katzenpost/sockatz/common"
)

var (
	// clients must start reading from their streams
	// or else the worker will abandon the stream
	connectDeadine = time.Minute

	// hmm
	sockatzEndpoint = "127.4.2.0:4242"

	// PayloadLen is the size of the transported payload
	// for QUIC it needs to be minimum ~1200b
	PayloadLen = 1200

	// time to wait before unblocking on Read() and returning ErrNoData
	DefaultDeadline = time.Millisecond * 100

	ErrShutdown          = errors.New("Halted")
	ErrNoData            = errors.New("ErrNoData")
	ErrSocketClosed      = errors.New("ErrSocketClosed")
	ErrInsufficientFunds = errors.New("ErrInsufficientFunds")
	ErrInvalidFrame      = errors.New("ErrInvalidFrame")
	ErrNoSession         = errors.New("ErrNoSession")
	ErrInvalidCommand    = errors.New("ErrInvalidCommand")
	ErrUnsupportedProto  = errors.New("ErrUnsupportedProtocol")
	ErrDialFailed        = errors.New("ErrDialFailed")
)

// SockatzServer is a kaetzchen responder that proxies
// a TCP connection to the host specified in a Stream
type Sockatz struct {
	cfg *config.Config
	worker.Worker
	log *logging.Logger
	logBackend *log.Backend

	sessions *sync.Map
}

// NewSockatz instantiates the Sockatz Kaetzchen responder
func NewSockatz(cfgFile string, logBackend *log.Backend) (*Sockatz, error) {
	cfg, err := config.LoadFile(cfgFile)
	log := logBackend.GetLogger("sockatz_server")
	if err != nil {
		return nil, err
	}
	s := &Sockatz{cfg: cfg, log: log, sessions: new(sync.Map)}
	return s, nil
}

type Command uint8

const (
	Dial Command = iota
	Topup
	Proxy
)

type Mode uint8

const (
	TCP Mode = iota
	UDP
)

// DialCommand encapsulates a Dial command sent to the service
type DialCommand struct {
	ID      []byte
	Target  *url.URL // supports tcp:// or udp://
	Payload []byte   // may send initial data frame
}

// Marshal implements cborplugin.Command
func (d *DialCommand) Marshal() ([]byte, error) {
	return cbor.Marshal(d)
}

// Unmarshal implements cborplugin.Command
func (d *DialCommand) Unmarshal(b []byte) error {
	return cbor.Unmarshal(b, d)
}

// DialResponse is a response to a DialCommand, and may return data
type DialResponse struct {
	Error   error
	Payload []byte
}

// Marshal implements cborplugin.Command
func (d *DialResponse) Marshal() ([]byte, error) {
	return cbor.Marshal(d)
}

// Unmarshal implements cborplugin.Command
func (d *DialResponse) Unmarshal(b []byte) error {
	return cbor.Unmarshal(b, d)
}

// ProxyCommand
type ProxyCommand struct {
	ID      []byte // session ID of an existing session
	Payload []byte // Encapsulated Payload
}

// Marshal implements cborplugin.Command
func (p *ProxyCommand) Marshal() ([]byte, error) {
	return cbor.Marshal(p)
}

// Unmarshal implements cborplugin.Command
func (p *ProxyCommand) Unmarshal(b []byte) error {
	return cbor.Unmarshal(b, p)
}

// ProxyResponse is response to a ProxyCommand
type ProxyResponse struct {
	Error   error
	Payload []byte
}

// Marshal implements cborplugin.Command
func (p *ProxyResponse) Marshal() ([]byte, error) {
	return cbor.Marshal(p)
}

// Unmarshal implements cborplugin.Command
func (p *ProxyResponse) Unmarshal(b []byte) error {
	return cbor.Unmarshal(b, p)
}

// TopupCommand adds time to a session ID with a Cashu payment
type TopupCommand struct {
	ID   []byte
	Nuts []byte
}

// Marshal implements cborplugin.Command
func (s *TopupCommand) Marshal() ([]byte, error) {
	return cbor.Marshal(s)
}

// Unmarshal implements cborplugin.Command
func (s *TopupCommand) Unmarshal(b []byte) error {
	return cbor.Unmarshal(b, s)
}

// TopupResponse is the response to a TopupCommand
type TopupResponse struct {
	Error error // ErrPaymentFailed, NoError
}

// Marshal implements cborplugin.Command
func (s *TopupResponse) Marshal() ([]byte, error) {
	return cbor.Marshal(s)
}

// Unmarshal implements cborplugin.Command
func (s *TopupResponse) Unmarshal(b []byte) error {
	return cbor.Unmarshal(b, s)
}

// Request implments cborplugin.Command and encapsulates this plugins protocol messages.
type Request struct {
	Command Command
	Payload []byte
}

// Marshal implements cborplugin.Command
func (s *Request) Marshal() ([]byte, error) {
	return cbor.Marshal(s)
}

// Unmarshal implements cborplugin.Command
func (s *Request) Unmarshal(b []byte) error {
	return cbor.Unmarshal(b, s)
}

// Response implments cborplugin.Command and encapsulates the plugin protocol messages
type Response struct {
	//Command Command
	Payload []byte
	Error   error
}

// Marshal implements cborplugin.Command
func (s *Response) Marshal() ([]byte, error) {
	return cbor.Marshal(s)
}

// Unarshal implements cborplugin.Command
func (s *Response) Unmarshal(b []byte) error {
	return cbor.Unmarshal(b, s)
}

// Session holds state associated with reliable in-order framing of transported TCP stream
type Session struct {

	s *Sockatz

	sync.Mutex
	// ID is the unique ID for this Session
	ID []byte

	// ValidUntil is when this Session needs to be renewed
	ValidUntil time.Time

	// Transport provides ordered stream from unreliable katzenpost messages
	// in this case, we're using QUIC as the transport
	Transport *common.KatConn

	// Target is the remote peer
	Target net.Conn

	// Mode
	Mode Mode
}

// Reset clears Session state
func (s *Session) Reset() {
	s.Lock()
	defer s.Unlock()
	if s.Target != nil {
		s.Target.Close()
		s.Target = nil
	}
}

// OnCommand implements cborplugin.ServicePlugin OnCommand
func (s *Sockatz) OnCommand(cmd cborplugin.Command) (cborplugin.Command, error) {
	switch r := cmd.(type) {
	case *cborplugin.Request:
		if !r.HasSURB {
			s.log.Notice("Got request with no SURB, no reply to send")
		}

		// deserialize Request.Payload into a sockatz Request
		req := &Request{}
		err := cbor.Unmarshal(r.Payload, req)
		if err != nil {
			s.log.Debugf("Got request that failed to unmarshal with %v", err)
			return nil, err
		}
		// Call the handler for the Command indicated
		switch req.Command {
		case Topup:
			s.log.Debugf("Got Topup Command")
			t := &TopupCommand{}
			if err := t.Unmarshal(req.Payload); err == nil {
				return wrapResponse(s.topup(t))
			}
		case Dial:
			s.log.Debugf("Got Dial Command")
			d := &DialCommand{}
			if err := d.Unmarshal(req.Payload); err == nil {
				return wrapResponse(s.dial(d))
			}
		case Proxy:
			s.log.Debugf("Got Proxy Command")
			p := &ProxyCommand{}
			if err := p.Unmarshal(req.Payload); err == nil {
				return wrapResponse(s.proxy(p))
			}
		default:
			s.log.Error("Got invalid Command %x", req.Command)
			return s.invalid(req)
		}
		s.log.Errorf("Unmarshal failure")
	default:
		s.log.Errorf("OnCommand called with unknown Command type")
		return nil, errors.New("Invalid Command type")
	}
	panic("NotReached")
}

// we need to return a cborplugin.Response
// https://github.com/katzenpost/katzenpost/issues/300
func wrapResponse(cmd cborplugin.Command, err error) (*cborplugin.Response, error) {
	if err != nil {
		return nil, err
	}
	p, err := cmd.Marshal()
	if err != nil {
		return nil, err
	}
	return &cborplugin.Response{Payload: p}, nil
}

func (s *Sockatz) dial(cmd *DialCommand) (*DialResponse, error) {
	reply := &DialResponse{}

	s.log.Debugf("Received DialCommand(%x, %s)", cmd.ID, cmd.Target)
	// locate an existing session by ID
	ss, err := s.findSession(cmd.ID)
	if err != nil {
		return nil, err
	}
	// clear any existing session state
	ss.Reset()

	// XXX: duplicate dial commands may reset the session state

	// Get a net.Conn for the target
	switch cmd.Target.Scheme {
	case "tcp":
		// start quic transport for tcp
		l :=s.logBackend.GetLogger(fmt.Sprintf("KatConn:%x", cmd.ID))
		ss.Transport = common.NewKatConn(l)
	case "udp":
		// XXX: Add proxy support
		conn, err := net.Dial("udp", cmd.Target.Host)
		if err != nil {
			ss.Target = conn
		} else {
			reply.Error = ErrDialFailed
		}
	case "":
		return nil, ErrUnsupportedProto
	}
	return reply, nil
}

// SendRecv reads and writes data from the sockets
func (s *Session) SendRecv(payload []byte) ([]byte, error) {
	s.s.log.Debugf("SendRecv()")
	s.s.log.Debugf("len(payload): %d", len(payload))

	// write packet to transport
	s.s.log.Debugf("WritePacket() (blocked)")
	_, err := s.Transport.WritePacket(payload)
	if err != nil {
		s.s.log.Errorf("WritePacket failure: %v", err)
		return nil, err
	}
	s.s.log.Debugf("WritePacket() (unblocked)")

	// read packet from transport
	buf := make([]byte, len(payload))
	s.s.log.Debugf("ReadPacket() (blocked)")
	n, err := s.Transport.ReadPacket(buf)
	if err != nil {
		s.s.log.Error("ReadPacket failure: %v", err)
		return nil, err
	}
	s.s.log.Debugf("ReadPacket() (unblocked)")
	s.s.log.Debugf("len(response): %d", n)
	return buf, nil
}

func (s *Sockatz) findSession(id []byte) (*Session, error) {
	ss, ok := s.sessions.Load(string(id))
	// no session found
	if !ok {
		s.log.Errorf("No Session found")
		return nil, ErrNoSession
	}

	// wrong type stored
	ses, ok := ss.(*Session)
	if !ok {
		s.log.Errorf("Invalid Session found")
		return nil, ErrNoSession
	}
	return ses, nil
}

func (s *Sockatz) topup(cmd *TopupCommand) (*TopupResponse, error) {
	// FIXME XXX: for testing only
	// validate topup
	// if !s.gotNuts(cmd.Nuts) {
	// 	return &TopupResponse{Error: ErrInsufficientFunds}
	// }
	s.log.Debugf("Received TopupCommand(%x, %x)", cmd.ID, cmd.Nuts[:16])

	if ss, ok := s.sessions.Load(string(cmd.ID)); ok {
		if ses, ok := ss.(*Session); ok {
			ses.ValidUntil = time.Now().Add(60 * time.Minute)
			s.sessions.Store(string(cmd.ID), ses)
		}
		panic("Invalid type in map")
	} else {
		ses := new(Session)
		ses.s = s
		ses.ID = cmd.ID
		s.sessions.Store(string(cmd.ID), ses)
	}
	return &TopupResponse{}, nil
}

func (s *Sockatz) proxy(cmd *ProxyCommand) (*ProxyResponse, error) {
	// deserialize cmd as a ProxyResponse
	reply := &ProxyResponse{}
	s.log.Debugf("Received ProxyCommand: %v", cmd)

	// locate an existing session by ID
	ss, err := s.findSession(cmd.ID)
	if err != nil {
		return nil, err
	}

	ss.Lock()
	defer ss.Unlock()

	// SendRecv writes payload and reads packets from the session connection
	rawReply, err := ss.SendRecv(cmd.Payload)

	if err != nil {
		reply.Error = err
		return reply, nil
	}
	reply.Payload = rawReply
	return reply, nil
}

func (s *Sockatz) invalid(cmd cborplugin.Command) (cborplugin.Command, error) {
	resp := Response{Error: ErrInvalidCommand}
	rawResp, err := resp.Marshal()
	if err != nil {
		return nil, err
	}
	return &cborplugin.Response{Payload: rawResp}, nil
}

func (s *Sockatz) RegisterConsumer(svr *cborplugin.Server) {
	s.log.Debugf("RegisterConsumer called")
}

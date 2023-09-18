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
	"context"
	"errors"
	"io"
	"net"
	"net/url"
	"os"
	"sync"
	"time"

	"github.com/katzenpost/katzenpost/core/log"
	"gopkg.in/op/go-logging.v1"

	"github.com/fxamacker/cbor/v2"
	"github.com/katzenpost/katzenpost/client/config"
	"github.com/katzenpost/katzenpost/core/worker"
	"github.com/katzenpost/katzenpost/katzensocks/cashu"
	"github.com/katzenpost/katzenpost/katzensocks/common"
	"github.com/katzenpost/katzenpost/server/cborplugin"
)

var (
	// clients must start reading from their streams
	// or else the worker will abandon the stream
	connectDeadine = time.Minute

	// PayloadLen is the size of the transported payload
	// for QUIC it needs to be minimum ~1200b
	PayloadLen = 1452

	// DefaultDeadline determines how long the worker will block reading
	// the QUICProxyConn socket for a reply after it has written the
	// client request payload to the socket.
	DefaultDeadline = 5000 * time.Millisecond

	ErrShutdown          = errors.New("Halted")
	ErrNoData            = errors.New("ErrNoData")
	ErrSocketClosed      = errors.New("ErrSocketClosed")
	ErrInsufficientFunds = errors.New("ErrInsufficientFunds")
	ErrInvalidFrame      = errors.New("ErrInvalidFrame")
	ErrNoSession         = errors.New("ErrNoSession")
	ErrInvalidCommand    = errors.New("ErrInvalidCommand")
	ErrUnsupportedProto  = errors.New("ErrUnsupportedProtocol")
	ErrDialFailed        = errors.New("ErrDialFailed")

	// Cashu configuration
	cashuWalletUrl = "http://localhost:4449"
)

// Server is a kaetzchen responder that proxies
// a TCP connection to the host specified in a Stream
type Server struct {
	cfg *config.Config
	worker.Worker
	log         *logging.Logger
	logBackend  *log.Backend
	payloadLen  int
	cashuClient *cashu.CashuApiClient
	sessions    *sync.Map
	write func(cborplugin.Command)
}

// NewServer instantiates the Katzensocks Kaetzchen responder
func NewServer(cfgFile string, logBackend *log.Backend) (*Server, error) {
	cfg, err := config.LoadFile(cfgFile)
	log := logBackend.GetLogger("katzensocks_server")
	if err != nil {
		return nil, err
	}
	cashuClient := cashu.NewCashuApiClient(nil, cashuWalletUrl)
	s := &Server{cfg: cfg, log: log, sessions: new(sync.Map), payloadLen: cfg.SphinxGeometry.UserForwardPayloadLength, cashuClient: cashuClient}
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

// DialStatus indicates success or failure
type DialStatus uint8

const (
	DialSuccess DialStatus = iota
	DialFailure
)

// DialResponse is a response to a DialCommand, and may return data
type DialResponse struct {
	Status  DialStatus
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

// ProxyStatus indicates success or failure
type ProxyStatus uint8

const (
	ProxySuccess ProxyStatus = iota
	ProxyInsufficientFunds
	ProxyFailure
)

// ProxyResponse is response to a ProxyCommand
type ProxyResponse struct {
	Status  ProxyStatus
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

// TopupStatus indicates success or failure
type TopupStatus uint8

const (
	TopupSuccess TopupStatus = iota
	TopupFailure
)

// TopupResponse is the response to a TopupCommand
type TopupResponse struct {
	Status TopupStatus
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
	s *Server

	sync.Mutex
	// ID is the unique ID for this Session
	ID []byte

	// ValidUntil is when this Session needs to be renewed
	ValidUntil time.Time

	// Transport provides ordered stream from unreliable katzenpost messages
	// in this case, we're using QUIC as the transport
	Transport *common.QUICProxyConn

	// Peer is the net.Addr of the client
	Peer net.Addr

	// Remote is the client endpoint
	Remote net.Conn

	// Target is the remote host to proxy to
	Target net.Conn

	// Mode
	Mode Mode

	// Errors ?
	Errors     chan error
	acceptOnce *sync.Once
}

// reset clears Session state
func (s *Session) reset() {
	if s.Target != nil {
		s.Target.Close()
		s.Target = nil
	}
	s.acceptOnce = new(sync.Once)
	s.Transport = nil
}

// OnCommand implements cborplugin.ServicePlugin OnCommand
func (s *Server) OnCommand(cmd cborplugin.Command) error {
	switch r := cmd.(type) {
	case *cborplugin.Request:
		// deserialize Request.Payload into a sockatz Request
		s.Go(func() {
			req := &Request{}
			err := cbor.Unmarshal(r.Payload, req)
			if err != nil {
				s.log.Error("Got request that failed to unmarshal with %v", err)
				return
			}

			// Call the handler for the Command indicated
			switch req.Command {
			case Topup:
				s.log.Debugf("Got Topup Command")
				t := &TopupCommand{}
				if err := t.Unmarshal(req.Payload); err == nil {
					s.topup(t)
				}
			case Dial:
				s.log.Debugf("Got Dial Command")
				d := &DialCommand{}
				if err := d.Unmarshal(req.Payload); err == nil {
					s.dial(d)
				}
			case Proxy:
				s.log.Debugf("Got Proxy Command")
				p := &ProxyCommand{}
				if err := p.Unmarshal(req.Payload); err == nil {
					s.proxy(p)
				}
			default:
				s.log.Error("Got invalid Command %x", req.Command)
				s.invalid(req)
			}
		})
		return nil
	default:
		s.log.Errorf("OnCommand called with unknown Command type")
		return errors.New("Invalid Command type")
	}
	panic("NotReached")
}

// we need to return a cborplugin.Response
// https://github.com/katzenpost/katzenpost/issues/300
func (s *Server) writeResponse(cmd cborplugin.Command) {
	p, err := cmd.Marshal()
	if err != nil {
		return
	}
	s.write(&cborplugin.Response{Payload: p})
}

func (s *Server) dial(cmd *DialCommand) {
	reply := &DialResponse{}

	s.log.Debugf("Received DialCommand(%x, %s)", cmd.ID, cmd.Target)
	// locate an existing session by ID
	ss, err := s.findSession(cmd.ID)
	if err != nil {
		s.log.Error("Failed to find session %x: %s", cmd.ID, err)
		return
	}
	// clear any existing session state
	if ss.Transport != nil {
		s.log.Error("Already had Transport?")
		return
	}

	// Get a net.Conn for the target
	switch cmd.Target.Scheme {
	case "tcp":
		s.log.Debugf("got tcp target %s", cmd.Target.Host)
		// start quic transport for tcp, listening on Addr given by client
		ss.Transport = common.NewQUICProxyConn(cmd.ID)

		// this could happen asynchronously from responding to Dial
		s.log.Debugf("dialing Target")
		conn, err := net.Dial("tcp", cmd.Target.Host)
		if err == nil {
			s.log.Debugf("Dialed target")
			ss.Target = conn
		} else {
			s.log.Debugf("Failed to Dial target")
			reply.Status = DialFailure
		}
	case "udp":
		// XXX: Add proxy support
		s.log.Debugf("got udp target %s", cmd.Target.Host)
		conn, err := net.Dial("udp", cmd.Target.Host)
		if err == nil {
			s.log.Debugf("Dialed target")
			ss.Target = conn
		} else {
			s.log.Debugf("Failed to Dial target")
			reply.Status = DialFailure
		}
	default:
		s.log.Errorf("Received DialCommand with unsupported protocol field")
		reply.Status = DialFailure
	}
	s.writeResponse(reply)
}

// Accept runs once per Session
func (s *Session) AcceptOnce(transport common.Transport) {
	s.acceptOnce.Do(func() {
		s.s.Go(func() {
			s.s.log.Debugf("Accepting Client")
			ctx, cancelFn := context.WithCancel(context.Background())
			defer cancelFn()
			go func() {
				select {
				case <-s.s.HaltCh():
					cancelFn()
				case <-ctx.Done():
				}
			}()
			conn, err := transport.Accept(ctx)
			if err != nil {
				s.s.log.Error("Failure Accepting: %v", err)
				return
			}
			s.s.log.Debugf("Accepted %v", conn.RemoteAddr())
			s.Lock()
			s.Remote = conn
			s.s.log.Debugf("Accepted %v", conn.RemoteAddr())
			if s.Errors != nil {
				panic("session.Errors not nil")
			}
			s.Errors = s.s.proxyWorker(s.Remote, s.Target)
			s.Unlock()
		})
	})
}

// SendRecv reads and writes data from the sockets
func (s *Session) SendRecv(payload []byte) ([]byte, error) {
	s.s.log.Debugf("SendRecv()")
	s.s.log.Debugf("len(payload): %d", len(payload))

	// write packet to transport
	s.Lock()
	defer s.Unlock()
	if s.Transport == nil { // wtf
		s.s.log.Error("SendRecv() called before Transport exists")
		return nil, errors.New("No Transport")
	}
	s.AcceptOnce(s.Transport)
	clientAddr := append(s.ID, []byte("client")...)
	dst := common.UniqAddr(clientAddr)

	// Read s.Errors
	select {
	case err := <-s.Errors:
		s.s.log.Error("SendRecv() session.Error: %v", err)
		s.reset()
		return nil, err
	default:
	}

	// WritePacket into transport
	if len(payload) != 0 {
		s.s.log.Debug("WritePacket(%d) from  %v", len(payload), dst)
		_, err := s.Transport.WritePacket(context.Background(), payload, dst)
		if err != nil {
			s.s.log.Errorf("WritePacket failure: %v", err)
			return nil, err
		}
	}

	// Read s.Errors
	select {
	case err := <-s.Errors:
		s.s.log.Error("SendRecv() session.Error: %v", err)
		s.reset()
		return nil, err
	default:
	}

	// read packet from transport
	buf := make([]byte, s.s.payloadLen)

	// XXX
	// DefaultDeadline controls how long the server will block reading a message
	// to send to the client. If there is no response available before DefaultDeadline,
	// then an empty payload is returned to the client.
	ctx, cancelFn := context.WithTimeout(context.Background(), DefaultDeadline)
	defer cancelFn()
	n, addr, err := s.Transport.ReadPacket(ctx, buf)
	switch err {
	case nil, os.ErrDeadlineExceeded:
	default:
		s.s.log.Error("ReadPacket failure: %v", err)
		return nil, err
	}
	// Read s.Errors
	select {
	case err := <-s.Errors:
		s.reset()
		if err == nil {
			// Connection Finished
			return buf[:n], io.EOF
		}
		s.s.log.Error("SendRecv() session.Error: %v", err)
		return nil, err
	default:
	}

	s.s.log.Debugf("got %d bytes to %v", n, addr)
	return buf[:n], nil
}

func (s *Server) findSession(id []byte) (*Session, error) {
	ss, ok := s.sessions.Load(string(id))
	// no session found
	if !ok {
		s.log.Errorf("No Session found for %x", id)
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

func (s *Server) topup(cmd *TopupCommand) {
	// validate topup
	cashuTokenStr := string(cmd.Nuts)
	permissive := true // topups always succeed
	_, err := s.cashuClient.Receive(cashu.ReceiveParameters{Token: &cashuTokenStr})
	if err != nil {
		s.log.Error("topup cashu: %v", err)
		if !permissive {
			s.writeResponse(&TopupResponse{Status: TopupFailure})
			return
		}
	}

	s.log.Debugf("Received TopupCommand(%x, %x)", cmd.ID, cmd.Nuts[:16])

	if ss, ok := s.sessions.Load(string(cmd.ID)); ok {
		if ses, ok := ss.(*Session); ok {
			ses.ValidUntil = time.Now().Add(60 * time.Minute)
			s.sessions.Store(string(cmd.ID), ses)
		}
	} else {
		ses := new(Session)
		ses.acceptOnce = new(sync.Once)
		ses.s = s
		ses.ID = cmd.ID
		ses.ValidUntil = time.Now().Add(60 * time.Minute)
		s.sessions.Store(string(cmd.ID), ses)
	}
	s.writeResponse(&TopupResponse{Status: TopupSuccess})
}

func (s *Server) proxyWorker(a, b net.Conn) chan error {
	s.log.Debug("Starting proxyWorker %v %v", a, b)
	errCh := make(chan error, 2)
	s.Go(func() {
		var wg sync.WaitGroup
		wg.Add(2)

		go func() {
			defer wg.Done()
			_, err := io.Copy(a, b)
			if err != nil {
				s.log.Errorf("proxyWorker io.Copy returned: %v", err)
				errCh <- err
			}
			s.log.Debugf("Closing %v", b)
			err = b.Close()
			if err != nil {
				s.log.Errorf("proxyWorker Close returned: %v", err)
			}
		}()
		go func() {
			defer wg.Done()
			_, err := io.Copy(b, a)
			if err != nil {
				s.log.Errorf("proxyWorker io.Copy returned: %v", err)
				errCh <- err
			}
			s.log.Debugf("Closing %v", a)
			err = a.Close()
			if err != nil {
				s.log.Errorf("proxyWorker Close returned: %v", err)
			}
		}()
		wg.Wait()
		close(errCh)
	})
	return errCh
}

func (s *Server) proxy(cmd *ProxyCommand) {
	// deserialize cmd as a ProxyResponse
	reply := &ProxyResponse{}
	s.log.Debugf("Received ProxyCommand: %x", cmd.ID)

	// locate an existing session by ID
	ss, err := s.findSession(cmd.ID)
	if err != nil {
		s.log.Debugf("Failed to find Session: %x", cmd.ID)
		return
	}

	// check balance of session
	if time.Now().After(ss.ValidUntil) {
		reply.Status = ProxyInsufficientFunds
		s.writeResponse(reply)
		return
	}

	// XXX: received messages after session reset ?
	if ss.Transport == nil {
		s.log.Errorf("Received ProxyCommand with no Transport")
		reply.Status = ProxyFailure
		s.writeResponse(reply)
		return
	}

	// SendRecv writes payload and reads packets from the session connection
	rawReply, err := ss.SendRecv(cmd.Payload)
	if err != nil {
		s.log.Errorf("SendRecv err: %v", err)
		reply.Status = ProxyFailure
		s.writeResponse(reply)
		return
	}
	reply.Status = ProxySuccess
	reply.Payload = rawReply
	s.writeResponse(reply)
}

func (s *Server) invalid(cmd cborplugin.Command) {
	resp := Response{Error: ErrInvalidCommand}
	rawResp, err := resp.Marshal()
	if err != nil {
		return
	}
	s.writeResponse(&cborplugin.Response{Payload: rawResp})
}

func (s *Server) RegisterConsumer(svr *cborplugin.Server) {
	s.write = svr.Write
}

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
	"net"
	"net/url"
	"os"
	"sync"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/katzenpost/katzenpost/client/config"
	"github.com/katzenpost/katzenpost/core/queue"
	"github.com/katzenpost/katzenpost/core/worker"
	"github.com/katzenpost/katzenpost/server/cborplugin"
)

var (
	// clients must start reading from their streams
	// or else the worker will abandon the stream
	connectDeadine = time.Minute

	// PayloadLen is the size of the transported payload
	// for QUIC it needs to be minimum ~1200b
	PayloadLen = 1200

	// time to wait before unblocking on Read() and returning ErrNoData
	DefaultDeadline = time.Millisecond * 100

	ErrShutdown          = errors.New("Halted")
	ErrNoData            = errors.New("ErrNoData")
	ErrSocketClosed      = errors.New("ErrSocketClosed")
	ErrInsufficientFunds = errors.New("ErrInsufficientFunds")
	ErrNoSession         = errors.New("ErrNoSession")
	ErrInvalidCommand    = errors.New("ErrInvalidCommand")
	ErrUnsupportedProto  = errors.New("ErrUnsupportedProtocol")
	ErrDialFailed        = errors.New("ErrDialFailed")
	ErrDuplicateFrame    = errors.New("ErrDuplicateFrame")
	// ErrOutOfOrderWrite is returned when a non-sequential write Frame is received.
	// In order to use non-bocking send, out-of-order frames must be re-assembled
	// in-order for transported TCP, and this isn't yet implemented.
	ErrOutOfOrderWrite = errors.New("ErrOutOfOrderWrite")
)

// SockatzServer is a kaetzchen responder that proxies
// a TCP connection to the host specified in a Stream
type Sockatz struct {
	cfg *config.Config
	worker.Worker
	log *logging.Logger

	sessions *sync.Map
}

// NewSockatz instantiates the Sockatz Kaetzchen responder
func NewSockatz(cfgFile string, log *logging.Logger) (*Sockatz, error) {
	cfg, err := config.LoadFile(cfgFile)
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

// Frame encapsulates data and adds a sequence number
type Frame struct {
	Mode    Mode   // TCP or UDP (unreliable) data
	Ack     uint64 // Acknowledgement of last seen Frame
	Num     uint64 // number of this Frame
	Payload []byte // transported data
}

// DialCommand encapsulates a Dial command sent to the service
type DialCommand struct {
	ID     []byte
	Target *url.URL // supports tcp:// or udp://
	Frame  *Frame   // may send initial data frame
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
	Error error
	Frame *Frame // XXX: NotImplemented, Unused.
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
	ID    []byte // session ID of an existing session
	Frame *Frame // Encapsulated Payload
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
	Error error
	Frame *Frame
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
	sync.Mutex
	// ID is the unique ID for this Session
	ID []byte

	// ValidUntil is when this Session needs to be renewed
	ValidUntil time.Time

	// LastAck is the last seen Ack
	LastAck uint64

	// ReadIdx is the Idx of the greatest sequential requested Frame
	ReadIdx uint64

	// WriteIdx is the Idx of the greatest sequential sent Frame
	WriteIdx uint64

	// RWin is the number of frames to return ahead of LastAck
	RWin uint64

	// Target is the remote peer
	Target net.Conn

	// Frames of data read from the remote peer
	// and stored until acknowleged
	Frames map[uint64]*Frame

	// Frames of data from the client, stored for re-ordering frames sequentially.
	// XXX: use a priority queue with a worker that wakes up on every frame received
	// and checks to see if it can send a frame
	ReorderBuffer *queue.PriorityQueue
}

// Reset clears Session state
func (s *Session) Reset() {
	s.Lock()
	defer s.Unlock()
	if s.Target != nil {
		s.Target.Close()
		s.Target = nil
		s.LastAck = 0
		s.ReadIdx = 0
		s.WriteIdx = 0
		s.Frames = make(map[uint64]*Frame)
		s.ReorderBuffer = queue.New()
	}
}

// NewSession initializes and returns a Session
func NewSession() *Session {
	return &Session{Frames: make(map[uint64]*Frame), ReorderBuffer: queue.New()}
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
			return nil, err
		}
		// Call the handler for the Command indicated
		switch req.Command {
		case Topup:
			t := &TopupCommand{}
			if err := t.Unmarshal(r.Payload); err == nil {
				return wrapResponse(s.topup(t))
			}
		case Dial:
			d := &DialCommand{}
			if err := d.Unmarshal(r.Payload); err == nil {
				return wrapResponse(s.dial(d))
			}
		case Proxy:
			p := &ProxyCommand{}
			if err := p.Unmarshal(r.Payload); err == nil {
				return wrapResponse(s.proxy(p))
			}
		default:
			return s.invalid(req)
		}
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
		// XXX: Add proxy support
		conn, err := net.Dial("tcp", cmd.Target.Host)
		if err != nil {
			ss.Target = conn
			if cmd.Frame != nil {
				//TODO: dial command may include sender's first
				//Frame of data to reduce round trip latency
			}
		} else {
			// return ErrDialFailed
			reply.Error = ErrDialFailed
		}
	case "udp":
		// XXX: Add proxy support
		conn, err := net.Dial("udp", cmd.Target.Host)
		if err != nil {
			ss.Target = conn
			if cmd.Frame != nil {
				//TODO: dial command may include sender's first
				//Frame of data to reduce round trip latency
			}
		} else {
			reply.Error = ErrDialFailed
		}
	case "":
		return nil, ErrUnsupportedProto
	}
	return reply, nil
}

// SendRecv sends a frame and returns a frame or error
func (s *Session) SendRecv(f *Frame) (*Frame, error) {
	// ignore duplicate frames that we've already seen
	err := s.deDup(f)
	if err != nil {
		return nil, err
	}

	// drop acknowledged frames
	err = s.handleAck(f)
	if err != nil {
		return nil, err
	}

	frame, err := s.readFrame()
	if err != nil {
		return nil, err
	}
	if frame == nil {
		panic("nil frame wtf")
	}
	return frame, nil
}

func (s *Session) handleAck(f *Frame) error {
	// update session state
	s.Lock()
	defer s.Unlock()
	// purge Ack'd frames
	if f.Ack > s.LastAck {
		for i := s.LastAck; i <= f.Ack; i++ {
			// XXX: verify the frame existed ? it's an error if missing
			delete(s.Frames, i)
		}
		s.LastAck = f.Ack
	}
	return nil
}

func (s *Session) deDup(f *Frame) error {
	// drop duplicate / retransmitted frames
	if f.Num < s.WriteIdx {
		return ErrDuplicateFrame
	}
	return nil
}

func (s *Session) sendFrame(f *Frame) error {
	s.Lock()
	defer s.Unlock()
	doSend := false
	switch {
	case f.Num < s.WriteIdx:
	case f.Num == s.WriteIdx:
		// f is the next sequential frame
		doSend = true
	case f.Num > s.WriteIdx:
		// Place Frame in ReorderBuffer (a priority queue)
		s.ReorderBuffer.Enqueue(f.Num, f)

		// Peek and check whether the next frame is available
		head := s.ReorderBuffer.Peek().Value.(*Frame)
		if head != nil && head.Num == s.WriteIdx {
			s.ReorderBuffer.Pop()
			// f points at the next sequential frame
			f = head
			doSend = true
		}
	}
	// send the next sequential frame and increment WriteIdx to point at next sequential Frame
	if doSend {
		s.WriteIdx += 1
		_, err := s.Target.Write(f.Payload)
		return err
	}
	// Frames are expected to arrive out-of-order, which is not an error.
	return nil
}

func (s *Session) readFrame() (*Frame, error) {
	s.Lock()
	defer s.Unlock()

	// XXX: Improve/Tune Acknowledgement protocol.
	// We can return frames of data read from the Target out-of-order, but eventually need
	// to retransmit unACK'd frames, and the client only ACK's the last sequentually read frame.
	// An improvement would be to re-request missing frames pre-emptively, or ACK frames received
	// out-of-order so that the server only retransmits unACK'd frames.
	// XXX: This can be tuned better. With RWin = 0, this will always re-send the next Unack'd Frame.
	if s.ReadIdx > s.LastAck+s.RWin {
		// dont read-ahead past some number of Ack'd frames
		// re-send s.LastAck + 1
		s.ReadIdx = s.LastAck + 1
	}

	// See if the frame is already cached (e.g. on retransmission)
	if v, ok := s.Frames[s.ReadIdx]; ok && v != nil {
		return v, nil
	}

	// Try to read a Frame of data from Target before deadline is exceeded
	f := &Frame{Payload: make([]byte, PayloadLen), Num: s.ReadIdx}
	switch s.Target.(type) {
	case *net.UDPConn:
		f.Mode = UDP
	case *net.TCPConn:
		f.Mode = TCP
	}

	// Try to read a full frame within the deadline (default 100ms)
	// XXX: Read() may block for (default) 100ms - do not exceed the Kaetzchen worker constraints
	// cfg.Debug.KaetzchenDelay is (default) 750ms maximum amount of time a request may take before
	// being dropped.
	s.Target.SetReadDeadline(time.Now().Add(DefaultDeadline))
	defer s.Target.SetReadDeadline(time.Time{})
	n, err := s.Target.Read(f.Payload)
	if err != nil {
		if errors.Is(err, os.ErrDeadlineExceeded) {
			// return ErrNoData rather than an empty Frame
			if n == 0 {
				// XXX: log short read
				return nil, ErrNoData
			}
		} else {
			return nil, err
		}
	}

	return f, nil
}

func (s *Sockatz) findSession(id []byte) (*Session, error) {
	ss, ok := s.sessions.Load(id)
	// no session found
	if !ok {
		return nil, ErrNoSession
	}

	// wrong type stored
	ses, ok := ss.(*Session)
	if !ok {
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

	if ss, ok := s.sessions.Load(cmd.ID); ok {
		if ses, ok := ss.(*Session); ok {
			ses.ValidUntil = time.Now().Add(60 * time.Minute)
			s.sessions.Store(cmd.ID, ses)
		}
		panic("Invalid type in map")
	} else {
		ses := NewSession()
		ses.ID = cmd.ID
		s.sessions.Store(cmd.ID, ses)
	}
	return &TopupResponse{}, nil
}

func (s *Sockatz) proxy(cmd *ProxyCommand) (*ProxyResponse, error) {
	// deserialize cmd as a DialCommand
	reply := &ProxyResponse{}

	// locate an existing session by ID
	ss, err := s.findSession(cmd.ID)
	if err != nil {
		return nil, err
	}

	ss.Lock()
	defer ss.Unlock()
	f, err := ss.SendRecv(cmd.Frame)

	if err != nil {
		reply.Error = err
		return reply, nil
	}
	reply.Frame = f
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

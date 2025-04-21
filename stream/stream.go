package stream

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/fxamacker/cbor/v2"
	"github.com/katzenpost/hpqc/bacap"
	"github.com/katzenpost/hpqc/rand"
	"github.com/katzenpost/katzenpost/client"
	"github.com/katzenpost/katzenpost/client2"
	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/worker"
	"io"
	"math"
	"os"
	"sync"
	"time"
)

const (
	keySize           = 32
	nonceSize         = 24
	no_ack            = math.MaxUint64
	defaultWindowSize = 7
)

var (
	hash               = sha256.New
	cborFrameOverhead  = 0
	retryDelay         = epochtime.Period       // how often to retransmit unacknowledged frames
	averageRetryRate   = epochtime.Period / 2   // how often to retransmit Get requests
	averageReadRate    = epochtime.Period / 256 // how often to send Get requests
	averageSendRate    = epochtime.Period / 256 // how often to send Put requests
	defaultTimeout     = 0 * time.Second
	ErrStreamClosed    = errors.New("Stream Closed")
	ErrFrameDecrypt    = errors.New("Failed to decrypt")
	ErrGeometryChanged = errors.New("Stream Payload Geometry Change")
	ErrInvalidAddr     = errors.New("Invalid StreamAddr")
	ErrHalted          = errors.New("Halted")
)

// FrameType indicates the state of Stream at the current Frame
type FrameType uint8

const (
	// StreamStart indicates that this is the first Frame in a Stream
	StreamStart FrameType = iota
	// StreamData indicates that this is a data carrying Frame in a Stream
	StreamData
	// StreamEnd indicates that this is the last Frame in a Stream
	StreamEnd
)

func ftStr(t FrameType) string {
	switch t {
	case StreamStart:
		return "StreamStart"
	case StreamData:
		return "StreamData"
	case StreamEnd:
		return "StreamEnd"
	default:
		return "StreamInvalid"
	}
}

// Frame is the container for Stream payloads and contains Stream metadata
// that indicates whether the Frame is the first, last, or an intermediary
// block. This
type Frame struct {
	Type FrameType
	// Ack is the sequence number of last consequtive frame seen by peer
	Id      uint64
	Ack     uint64
	Payload []byte // transported data
}

// String returns a description of the frame and payload
func (f *Frame) String() string {
	return fmt.Sprintf("%s %d %d %s", ftStr(f.Type), f.Id, f.Ack, base64.StdEncoding.EncodeToString(f.Payload))
}

// StreamState are the states that the reader and writer routines can be in
type StreamState uint8

const (
	StreamOpen StreamState = iota
	StreamClosing
	StreamClosed
)

// ssStr displays stream state
func ssStr(s StreamState) string {
	switch s {
	case StreamOpen:
		return "StreamOpen"
	case StreamClosing:
		return "StreamClosing"
	case StreamClosed:
		return "StreamClosed"
	}
	return "StreamInvalid"
}

// StreamMode is the type of stream.
//
//	EndToEnd streams require the reader to acknowledge frames of data read
//	  before a sender will continue transmitting.
//	Multicast streams are suitable for multiple readers and do not
//	  ACK frames nor block the writer by waiting for ACKs.
//	The default StreamMode is EndToEnd.
type StreamMode uint8

const (
	Multicast StreamMode = iota // no Acknowledgements
	EndToEnd                    // requires interactive Acknowledge
)

// FrameWithPriority implmeents client.Item and holds the retransmit deadline and Frame for use with a TimerQueue
type FrameWithPriority struct {
	FramePriority uint64   // the time in nanoseconds of when to retransmit an unacknowledged message
	FrameID       uint64   // FrameID is used for end to end acknowldgements and retransmissions
	ID            [32]byte // box ID to write to
	Signature     [64]byte
	Ciphertext    []byte
}

// Priority implements client.Item interface; used by TimerQueue for retransmissions
func (s *FrameWithPriority) Priority() uint64 {
	return s.FramePriority
}

// nextEpoch returns a FrameWithPriority for next epoch
func nextEpoch(f *FrameWithPriority) *FrameWithPriority {
	_, _, til := epochtime.Now()
	f.FramePriority = uint64(time.Now().Add(til).UnixNano())
	return f
}

// nextSRV returns a FrameWithPriority for the next shared random epoch
func nextSRV(f *FrameWithPriority) *FrameWithPriority {
	epoch, _, til := epochtime.Now()
	// XXX: this isn't how we define the weekly srv rotation yet, #689
	epochsLeft := epochtime.WeekOfEpochs - (epoch % epochtime.WeekOfEpochs)
	timeLeft := til + time.Duration(epochsLeft*uint64(epochtime.Period))
	when := time.Now().Add(timeLeft).UnixNano()

	// XXX: add some noise to avoid stampeding herd
	f.FramePriority = uint64(when)
	return f
}

type stream Stream

func (s *Stream) MarshalCBOR() ([]byte, error) {
	s.l.Lock()
	s.R.Lock()
	defer s.l.Unlock()
	defer s.R.Unlock()
	s.ReadBuf = s.readBuf.Bytes()
	s.WriteBuf = s.writeBuf.Bytes()
	return cbor.Marshal((*stream)(s))
}

func (s *Stream) UnmarshalCBOR(data []byte) error {
	s.l.Lock()
	s.R.Lock()
	defer s.l.Unlock()
	defer s.R.Unlock()

	err := cbor.Unmarshal(data, (*stream)(s))
	if err != nil {
		return err
	}

	// initialize buffers
	s.readBuf = bytes.NewBuffer(s.ReadBuf)
	s.writeBuf = bytes.NewBuffer(s.WriteBuf)
	return nil
}

type Stream struct {
	l *sync.Mutex
	worker.Worker

	// Transport holds the storage interface Put(addr []byte, payload []byte) and Get([]addr)
	// that is used to send and receive ciphertexts
	transport Transport

	// statefulWriter and statefulReader provide sequental access with forward secrecy and
	// modify ReadCap and WriteCap's HKDF save state on each operation
	sw *bacap.StatefulWriter
	sr *bacap.StatefulReader

	// ctx
	Context []byte

	// ReadCap is the bacap UniversalReadCap of the peer we are reading from
	ReadCap *bacap.UniversalReadCap

	// WriteCap is the bacap OwnerCap of our own sequence of messages we write
	WriteCap *bacap.BoxOwnerCap

	startOnce *sync.Once

	// address of the Stream
	Addr *StreamAddr

	// Initiator is true if Stream is created by NewStream or Listen methods
	Initiator bool

	// Mode indicates what type of Stream, e.g. EndToEnd or Finite
	Mode StreamMode

	retryExpDist  *client2.ExpDist
	readerExpDist *client2.ExpDist
	senderExpDist *client2.ExpDist

	WriteBuf []byte
	writeBuf *bytes.Buffer // buffer to enqueue data before being transmitted
	ReadBuf  []byte
	readBuf  *bytes.Buffer // buffer to reassumble data from Frames

	// our frame pointers
	ReadIdx  uint64
	WriteIdx uint64

	// idx of last ack
	AckIdx uint64

	// last ack received from peer
	PeerAckIdx uint64

	// TQ is used to schedule retransmission events of unacknowledged messages
	TQ *client.TimerQueue

	// R holds state needed to reschedule unacknowledged messages expiring in TQ
	R *ReTx

	// Parameters

	// PayloadSize is the stream frame payload length, and must not change once
	// a stream has been initialized.
	PayloadSize int

	// WindowSize is the number of messages ahead of peer's
	// ackknowledgement that the writeworker will periodically retransmit
	WindowSize uint64

	// MaxWriteBufSize is the number of bytes to buffer before blocking calls to Write()
	MaxWriteBufSize int

	// RState indicates Reader State
	RState StreamState

	// RState indicates Writer State
	WState StreamState

	// timeout value used internally before failing a blocking call
	Timeout time.Duration

	// onFlush signals writer worker to wake and transmit frames
	onFlush       chan struct{}
	onAck         chan struct{}
	onWrite       chan struct{}
	onRead        chan struct{}
	onStreamClose chan struct{}
}

func (s *Stream) SetTransport(t Transport) {
	s.l.Lock()
	defer s.l.Unlock()
	s.transport = t
	// XXX: if stream is not new this should be checked
	s.PayloadSize = PayloadSize(t)
}

// ReTx implmements client.nqueue and re-transmits unacknowledged frames
type ReTx struct {
	sync.Mutex
	s    *Stream
	Wack map[uint64]*FrameWithPriority
}

// Ack removes any unAcknowledged Frames <= frameId from Wack
func (r *ReTx) Ack(frameId uint64) bool {
	ackD := false
	r.Lock()

	todelete := []uint64{}
	// ack predecessor frames to frameId
	for i, _ := range r.Wack {
		if i <= frameId {
			todelete = append(todelete, i)
			ackD = true
		}
	}
	for _, i := range todelete {
		delete(r.Wack, i)
	}
	r.Unlock()
	return ackD
}

// Push is called by the TimerQueue (Stream.TQ) with a client.Item when its deadline expires.
func (r *ReTx) Push(i client.Item) error {
	// time to retransmit a block that has not been acknowledged yet
	m, ok := i.(*FrameWithPriority)
	if !ok {
		panic("must be FrameWithPriority")
	}

	r.Lock()
	_, ok = r.Wack[m.FrameID]
	r.Unlock()
	if !ok {
		// Already Acknowledged
		return nil
	}

	// add a sampled retry delay to retransmit if unacknowledged
	mRng := rand.NewMath()
	delaySample := time.Duration(uint64(rand.Exp(mRng, float64(1/float64(retryDelay)))))
	m.FramePriority = uint64(time.Now().Add(delaySample).UnixNano())

	// transmit and schedule for retransmission from goroutine
	// do not block Push() on txFrame BlockingSend
	r.s.Go(func() {
		r.s.txEnqueue(m)
		err := r.s.txFrame(m)
		if err == nil {
			r.s.doOnWrite()
		}
	})
	return nil
}

// reader polls receive window of messages and adds to the reader queue
func (s *Stream) reader() {
	for {
		s.l.Lock()
		doFlush := false
		switch s.RState {
		case StreamClosed:
			// No more frames will be sent by peer
			// If ReliableStream, send final Ack
			s.l.Unlock()
			s.doFlush()
			return
		case StreamOpen:
			// prod writer to Ack
			if s.Mode == EndToEnd {
				if s.ReadIdx-s.AckIdx > s.WindowSize {
					doFlush = true
				}
			}
		default:
			// pass
		}
		s.l.Unlock()
		if doFlush {
			s.doFlush()
		}

		// read next frame
		select {
		case <-s.HaltCh():
			return
		case <-s.readerExpDist.OutCh():
		}

		f, err := s.readFrame()
		switch err {
		case nil:
		default:
			select {
			case <-s.HaltCh():
				return
			default:
			}
			continue
		}

		s.l.Lock()
		// process Acks
		if s.Mode == EndToEnd {
			s.processAck(f)
		}
		n, _ := s.readBuf.Write(f.Payload)

		// If this is the last Frame in the stream, set RState to StreamClosed
		if f.Type == StreamEnd {
			s.RState = StreamClosed
		} else {
			s.ReadIdx += 1
		}
		// signal to a caller blocked on Read() that there is data or EOF
		if f.Type == StreamEnd || n > 0 {
			s.l.Unlock()
			s.doOnRead()
			s.doFlush() // prod sleeping writer
		} else {
			s.l.Unlock()
		}
	}
}

// caller must hold s.l.Lock, and returns with lock held
// sleepReader sleeps until a Timeout occurs, data is available, or the
func (s *Stream) sleepReader() error {
	if s.readBuf.Len() == 0 {
		if s.RState == StreamClosed {
			return io.EOF
		} // otherwise continue below, and wait for data to be available
	} else {
		return nil // do not block Read, data is available
	}

	defer s.l.Lock() // in either case, return holding mutex
	// Timeout == 0 is a special case that doesn't need a time.Timer
	if s.Timeout != 0 {
		s.l.Unlock()
		select {
		case <-time.After(s.Timeout):
			return os.ErrDeadlineExceeded
		case <-s.HaltCh():
			return io.EOF
		case <-s.onRead:
			// awaken on StreamData or StreamEnd
		}
	} else {
		s.l.Unlock()
		select {
		case <-s.HaltCh():
			return io.EOF
		case <-s.onRead:
			// awaken on StreamData or StreamEnd
		}
	}
	return nil
}

// Read impl io.Reader
func (s *Stream) Read(p []byte) (n int, err error) {
	s.l.Lock()
	defer s.l.Unlock()
	err = s.sleepReader() // sleepReader returns holding mutex
	if err != nil {
		return
	}
	// if sleepReader returns in RState.StreamClosed, check if there are
	// any bytes to drain to the caller of Read, and subsequent calls to
	// Read will return io.EOF when the readBuf is drained.
	n, err = s.readBuf.Read(p)
	// ignore io.EOF on short reads from readBuf
	if err == io.EOF {
		if s.RState != StreamClosed || n > 0 {
			return n, nil
		}
	}
	return n, err
}

// caller must hold s.l mutex, and returns with mutex held
func (s *Stream) sleepWriter() error {
	// only sleep if there is nothing to do
	if s.writeBuf.Len() >= s.MaxWriteBufSize {
		defer s.l.Lock() // in either case, return holding mutex
		// Timeout == 0 blocks until there is a write or the stream is halted
		if s.Timeout != 0 {
			s.l.Unlock()
			select {
			case <-time.After(s.Timeout):
				return os.ErrDeadlineExceeded
			case <-s.HaltCh():
				return io.EOF
			case <-s.onWrite:
			}
		} else {
			s.l.Unlock()
			select {
			case <-s.HaltCh():
				return io.EOF
			case <-s.onWrite:
			}
		}
	}
	return nil
}

// Write impl io.Writer
func (s *Stream) Write(p []byte) (n int, err error) {
	// writes message with our last read pointer as header
	s.l.Lock()
	// buffer data to bytes.Buffer
	if s.WState == StreamClosed || s.WState == StreamClosing {
		s.l.Unlock()
		return 0, io.EOF
	}
	// sleepWriter sleeps until woken; and returns holding s.l.Lock
	err = s.sleepWriter()
	if err != nil {
		s.l.Unlock()
		return 0, err
	}

	// if stream closed, abort Write
	if s.WState == StreamClosed || s.WState == StreamClosing {
		s.l.Unlock()
		<-s.onStreamClose
		return 0, io.EOF
	}
	n, err = s.writeBuf.Write(p)
	// doFlush must not be called holding mutex
	s.l.Unlock()
	s.doFlush()
	return
}

// Sync() blocks until Stream.WriteBuf is flushed
func (s *Stream) Sync() error {
	s.l.Lock()
	if s.WState != StreamOpen {
		s.l.Unlock()
		return ErrStreamClosed
	}
	s.l.Unlock()
	for {
		s.l.Lock()
		if s.writeBuf.Len() == 0 {
			s.l.Unlock()
			return nil
		}
		s.l.Unlock()
		select {
		case <-s.onWrite:
		case <-s.HaltCh():
			return ErrHalted
		}
	}
}

// Close terminates the Stream with a final Frame and blocks future Writes
// it does *not* drain writeBuf, call Sync() to flush writeBuf first.
func (s *Stream) Close() error {
	s.l.Lock()
	if s.WState == StreamOpen {
		s.WState = StreamClosing
		s.l.Unlock()
		s.doFlush()       // wake up a sleeping writer !
		<-s.onStreamClose // block until writer has finalized
		return nil
	}
	s.l.Unlock()
	return nil
}

func (s *Stream) writer() {
	for {

		select {
		case <-s.HaltCh():
			return
		case <-s.senderExpDist.OutCh():
		}
		mustAck := false
		mustWaitForAck := false
		mustTeardown := false
		s.l.Lock()
		switch s.WState {
		case StreamClosed:
			close(s.onStreamClose)
			s.l.Unlock()
			return
		case StreamOpen, StreamClosing:
			if s.WState == StreamOpen {
			} else {
			}
			if s.Mode == EndToEnd {
				if s.ReadIdx-s.AckIdx > s.WindowSize {
					mustAck = true
				}
				if s.WriteIdx-s.PeerAckIdx > s.WindowSize {
					mustWaitForAck = true
				}
			}
			if s.RState == StreamClosed || s.WState == StreamClosing {
				mustTeardown = true
				if s.WState != StreamClosing {
					s.WState = StreamClosing
				}
				if s.Mode == EndToEnd {
					// When tearing down, we must ACK
					if s.ReadIdx-s.AckIdx > 1 {
						mustAck = true
					}
				}
			}
			if !mustAck && !mustTeardown {
				mustWaitForData := s.writeBuf.Len() == 0
				if mustWaitForData {
				}
				if mustWaitForAck {
				}
				mustWait := mustWaitForAck || mustWaitForData

				if s.WState == StreamClosing {
					mustWait = false
				}
				if mustWait {
					s.l.Unlock()
					select {
					case <-s.onFlush:
					case <-s.onAck:
					case <-s.HaltCh():
						return
					}
					continue // re-evaluate all of the conditions above after wakeup!
				}
			}
		}

		f := new(Frame)
		f.Id = s.WriteIdx

		// Set frame Ack if EndToEnd
		if s.Mode == EndToEnd {
			if s.ReadIdx > 0 {
				s.AckIdx = s.ReadIdx - 1
			} else {
				f.Ack = no_ack
			}
			f.Ack = s.AckIdx
		}

		if mustTeardown {
			// final Ack and frame transmitted
			s.WState = StreamClosed
			f.Type = StreamEnd
		} else if f.Id != 0 {
			f.Type = StreamData
		}
		f.Payload = make([]byte, s.PayloadSize)
		// Read up to the maximum frame payload size
		n, err := s.writeBuf.Read(f.Payload)
		mode := s.Mode
		s.l.Unlock()
		switch err {
		case nil, io.ErrUnexpectedEOF, io.EOF:
		default:
		}
		f.Payload = f.Payload[:n]
		if n > 0 || mustAck || mustTeardown {
			s.WriteIdx += 1
			fw, err := s.encFrame(f)
			if err != nil {
				// Fatal
				return
			}
			// schedules a retransmission in the next epoch if not acknowledged
			if mode == EndToEnd && !mustTeardown {
				s.txEnqueue(nextEpoch(fw))
			}

			err = s.txFrame(fw)
			switch err {
			case nil:
				s.doOnWrite()
			default:
			}
		}
	}
}

// encFrame encrypts frame and returns the box ID, ciphertet and signature as a FrameWithPriority
func (s *Stream) encFrame(frame *Frame) (*FrameWithPriority, error) {
	serialized, err := cbor.Marshal(frame)
	if err != nil {
		return nil, err
	}

	// zero extend payload
	if s.PayloadSize-len(serialized) > 0 {
		padding := make([]byte, s.PayloadSize-len(serialized))
		serialized = append(serialized, padding...)
	}

	// encrypt frame and return the boxID
	boxID, ciphertext, sig, err := s.sw.EncryptNext(serialized)
	if err != nil {
		return nil, err
	}
	sig64 := [64]byte{}
	copy(sig64[:], sig)

	return &FrameWithPriority{FrameID: frame.Id, ID: boxID, Ciphertext: ciphertext, Signature: sig64}, nil
}

// txFrame transmits a ciphertext over the wire
func (s *Stream) txFrame(f *FrameWithPriority) error {
	var ctx context.Context
	var cancelFn func()
	if s.Timeout != 0 {
		ctx, cancelFn = context.WithTimeout(context.Background(), s.Timeout)
		defer cancelFn()
	} else {
		// this should probably not block for longer than 1 epoch
		ctx, cancelFn = context.WithTimeout(context.Background(), epochtime.Period)
		defer cancelFn()
	}
	return s.transport.Put(ctx, f.ID, f.Signature, f.Ciphertext)
}

func (s *Stream) txEnqueue(m *FrameWithPriority) {
	// use a timerqueue here and set an acknowledgement retransmit timeout; ideally we would know the effective durability of the storage medium and maximize the retransmission delay so that we retransmit a message as little as possible.
	s.R.Lock()
	s.R.Wack[m.FrameID] = m
	s.R.Unlock()
	s.TQ.Push(m)
}

func (s *Stream) doFlush() {
	select {
	case s.onFlush <- struct{}{}:
	default:
	}
}

func (s *Stream) doOnRead() {
	select {
	case s.onRead <- struct{}{}:
	default:
	}
}

func (s *Stream) doOnWrite() {
	select {
	case s.onWrite <- struct{}{}:
	default:
	}
}

func (s *Stream) readFrame() (*Frame, error) {
	s.l.Lock()
	idx := s.ReadIdx
	box_id, err := s.sr.NextBoxID()
	s.l.Unlock()
	if err != nil {
		return nil, err
	}
	ctx, cancelFn := context.WithCancel(context.Background())
	s.Go(func() {
		select {
		case <-s.HaltCh():
			cancelFn()
		case <-s.retryExpDist.OutCh(): // retransmit unacknowledged requests periodically
			cancelFn()
		case <-ctx.Done():
		}
	})

	ciphertext, sig, err := s.transport.Get(ctx, box_id.ByteArray())
	cancelFn()
	if err != nil {
		//panic(err)
		return nil, err
	}

	plaintext, err := s.sr.DecryptNext(s.Context, box_id.ByteArray(), ciphertext, sig)
	if err != nil {
		panic(err)
		return nil, err
	}

	f := new(Frame)
	f.Id = idx
	_, err = cbor.UnmarshalFirst(plaintext, f)
	if err != nil {
		panic(err)
		return nil, err
	}
	return f, nil
}

func (s *Stream) processAck(f *Frame) {
	// Nothing is acknowledged
	if f.Ack == no_ack || s.Mode != EndToEnd {
		return
	}
	// update last_ack from peer
	if f.Ack > s.PeerAckIdx || s.PeerAckIdx == no_ack {
		s.PeerAckIdx = f.Ack
	}
	ackD := s.R.Ack(f.Ack)

	// prod writer() waiting on Ack
	if ackD {
		select {
		case s.onAck <- struct{}{}:
		default:
		}
	}
}

// StreamAddr implements net.Addr
type StreamAddr struct {
	Secret string
}

// Network implements net.Addr
func (s *StreamAddr) Network() string {
	return ""
}

// String implements net.Addr String()
func (s *StreamAddr) String() string {
	return s.Secret
}

// LocalAddr implements net.Addr LocalAddr()
func (s *Stream) LocalAddr() *StreamAddr {
	return s.Addr
}

// LocalAddr implements net.Conn RemoteAddr()
func (s *Stream) RemoteAddr() *StreamAddr {
	return s.Addr
}

// Transport describes the interface to Get or Put Frames
type Transport interface {
	Get(ctx context.Context, addr [32]byte) (ciphertext []byte, signature [64]byte, err error)
	Put(ctx context.Context, addr [32]byte, signature [64]byte, payload []byte) error
	PayloadSize() int
}

func newStream(mode StreamMode) *Stream {
	s := new(Stream)
	s.Addr = new(StreamAddr)
	s.Mode = mode
	s.l = new(sync.Mutex)
	s.startOnce = new(sync.Once)
	s.RState = StreamOpen
	s.WState = StreamOpen
	s.Timeout = defaultTimeout
	// timerqueue calls s.Push when timeout of enqueued item
	s.R = &ReTx{s: s}
	s.R.Wack = make(map[uint64]*FrameWithPriority)
	s.TQ = client.NewTimerQueue(s.R)
	s.retryExpDist = client2.NewExpDist()
	s.readerExpDist = client2.NewExpDist()
	s.senderExpDist = client2.NewExpDist()
	s.writeBuf = new(bytes.Buffer)
	s.readBuf = new(bytes.Buffer)

	s.AckIdx = no_ack
	s.PeerAckIdx = no_ack
	return s
}

// NewMulticastSendStream returns a Multicast Writer with no Acknowledgements
func NewMulticastSendStream(t Transport, writeCap *bacap.BoxOwnerCap) *Stream {
	st := newStream(Multicast)
	st.WriteCap = writeCap
	st.SetTransport(t)
	return st
}

// NewMulticastRecvStream returns a Multicast Reader with no Acknowledgements
func NewMulticastRecvStream(t Transport, readCap *bacap.UniversalReadCap) *Stream {
	st := newStream(Multicast)
	st.ReadCap = readCap
	st.SetTransport(t)
	return st
}

// NewStream generates a new address and initializes a Stream as listener. It does not start it.
func NewStream(t Transport, writeCap *bacap.BoxOwnerCap, readCap *bacap.UniversalReadCap, context []byte) *Stream {
	st := newStream(EndToEnd)
	st.ReadCap = readCap
	st.WriteCap = writeCap
	st.Context = context
	st.SetTransport(t)
	return st
}

// LoadStream initializes a Stream from state saved by Save()
func LoadStream(state []byte) (*Stream, error) {
	st := newStream(EndToEnd)
	st.ReadCap = &bacap.UniversalReadCap{}
	st.WriteCap = &bacap.BoxOwnerCap{}

	_, err := cbor.UnmarshalFirst(state, st)
	if err != nil {
		return nil, err
	}

	return st, nil
}

// Save serializes the current state of the Stream
func (s *Stream) Save() ([]byte, error) {
	return cbor.Marshal(s)
}

// Start starts the reader and writer workers
func (s *Stream) Start() {
	s.StartWithTransport(nil)
}

// String returns a description of the stream
func (s *Stream) String() string {
	addr := s.Addr.String()
	unACKdstats := ""
	s.R.Lock()
	for id, f := range s.R.Wack {
		unACKdstats += fmt.Sprintf("UnAcked: Frame: %d BoxID: %x\n", id, f.ID)
	}
	s.R.Unlock()
	rwState := fmt.Sprintf("%v %v\n", ssStr(s.RState), ssStr(s.WState))
	stateStats := fmt.Sprintf("%v %v\n", s.AckIdx, s.PeerAckIdx)
	s.l.Lock()
	bufStats := fmt.Sprintf("readBuf.Len(): %v writeBuf.Len(): %v", s.readBuf.Len(), s.writeBuf.Len())
	s.l.Unlock()
	return addr + rwState + stateStats + unACKdstats + bufStats
}

// StartWithTransport starts the reader and writer workers
func (s *Stream) StartWithTransport(trans Transport) {
	if trans != nil {
		s.SetTransport(trans)
	}
	s.startOnce.Do(func() {
		s.Go(s.setDefaultPollingRates)
		s.Go(func() {
			<-s.HaltCh()
			s.retryExpDist.Halt()
			s.readerExpDist.Halt()
			s.senderExpDist.Halt()
			s.TQ.Halt()
		})
		// re-schedule unacknowledged frames
		s.Go(func() {
			s.R.Lock()
			for _, f := range s.R.Wack {
				f := f
				defer s.txEnqueue(f)
			}
			s.R.Unlock()
		})

		// sequential reads and writes using bacap using the StatefulReader and StatefulWriter helper types
		// for each stream we always use a unique context so that with one UniversalReadCap
		// from a PAKE we can create many different streams.
		sr, err := bacap.NewStatefulReader(s.ReadCap, s.Context)
		if err != nil {
			panic(err)
		}
		sw, err := bacap.NewStatefulWriter(s.WriteCap, s.Context)
		if err != nil {
			panic(err)
		}
		s.sr, s.sw = sr, sw

		s.WindowSize = defaultWindowSize
		s.MaxWriteBufSize = int(s.WindowSize) * PayloadSize(s.transport)
		s.onFlush = make(chan struct{}, 1)
		s.onAck = make(chan struct{}, 1)
		s.onStreamClose = make(chan struct{})
		s.onWrite = make(chan struct{})
		s.onRead = make(chan struct{})
		s.TQ.Start()

		// In Mode Multicast, a Stream may be either a
		if s.Mode == Multicast {
			if s.ReadCap != nil {
				s.Go(s.reader)
			} else {
				s.Go(s.writer)
			}
		} else {
			s.Go(s.reader)
			s.Go(s.writer)
		}
	})
}

// setDefaultPollingRates sets default intervals for the exponential distribution repeat request parameters
func (s *Stream) setDefaultPollingRates() {
	// set connected status online to
	s.retryExpDist.UpdateConnectionStatus(true)
	s.readerExpDist.UpdateConnectionStatus(true)
	s.senderExpDist.UpdateConnectionStatus(true)

	s.retryExpDist.UpdateRate(uint64(averageRetryRate/time.Millisecond), uint64(epochtime.Period/time.Millisecond))
	s.readerExpDist.UpdateRate(uint64(averageReadRate/time.Millisecond), uint64(epochtime.Period/time.Millisecond))
	s.senderExpDist.UpdateRate(uint64(averageSendRate/time.Millisecond), uint64(epochtime.Period/time.Millisecond))
}

func init() {
	b, _ := cbor.Marshal(Frame{})
	cborFrameOverhead = len(b)
}

// Payloadsize returns the maximum frame size that can be sent with Transport
func PayloadSize(c Transport) int {
	bacapOverhead := 0 // XXX: what is bacap overhead
	return c.PayloadSize() - cborFrameOverhead - bacapOverhead
}

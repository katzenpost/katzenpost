package stream

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"github.com/fxamacker/cbor/v2"
	"github.com/katzenpost/katzenpost/client"
	"github.com/katzenpost/katzenpost/core/crypto/rand"
	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/worker"
	mClient "github.com/katzenpost/katzenpost/map/client"
	"github.com/katzenpost/katzenpost/map/common"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/nacl/secretbox"
	"io"
	"os"
	"sync"
	"time"
)

const (
	keySize   = 32
	nonceSize = 24
)

var (
	retryDelay       = epochtime.Period / 16
	defaultTimeout   = 5 * time.Minute
	FramePayloadSize int
	ErrStreamClosed  = errors.New("Stream Closed")
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

// Frame is the container for Stream payloads and contains Stream metadata
// that indicates whether the Frame is the first, last, or an intermediary
// block. This
type Frame struct {
	Type FrameType
	// Ack is the sequence number of last consequtive frame seen by peer
	id      uint64
	Ack     uint64
	Payload []byte // transported data
}

type StreamState uint8

const (
	StreamOpen StreamState = iota
	StreamClosing
	StreamClosed
)

// smsg is some sort of container for written messages pending acknowledgement
type smsg struct {
	f        *Frame // payload of message
	priority uint64 // timeout, for when to retransmit if the message is not acknowledged
}

// Priority implements client.Item interface; used by TimerQueue for retransmissions
func (s *smsg) Priority() uint64 {
	return s.priority
}

type Stream struct {
	sync.Mutex
	worker.Worker

	c *mClient.Client `cbor:"-"`
	// frame encryption secrets
	WriteKey *[keySize]byte // secretbox key to encrypt with
	ReadKey  *[keySize]byte // secretbox key to decrypt with

	// read/write secrets initialized from handshake
	WriteIDBase common.MessageID
	ReadIDBase  common.MessageID

	// buffers
	WriteBuf *bytes.Buffer // buffer to enqueue data before being transmitted
	ReadBuf  *bytes.Buffer // buffer to reassumble data from Frames

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

// glue for timerQ
type ReTx struct {
	sync.Mutex
	s    *Stream
	Wack map[uint64]struct{}
}

// Push implements the client.nqueue interface
func (r *ReTx) Push(i client.Item) error {
	// time to retransmit a block that has not been acknowledged yet
	m, ok := i.(*smsg)
	if !ok {
		panic("must be smsg")
	}

	r.Lock()
	_, ok = r.Wack[m.f.id]
	r.Unlock()
	if !ok {
		// Already Acknowledged
		return nil
	}
	return r.s.txFrame(m.f)
}

// reader polls receive window of messages and adds to the reader queue
func (s *Stream) reader() {
	for {
		s.Lock()
		switch s.RState {
		case StreamClosed:
			// No more frames will be sent by peer
			// If ReliableStream, send final Ack
			if s.ReadIdx > s.AckIdx {
				s.doFlush()
			}
			s.Unlock()
			return
		case StreamOpen:
			// prod writer to Ack
			if s.ReadIdx-s.AckIdx >= s.WindowSize {
				s.doFlush()
			}
		}
		s.Unlock()

		// read next frame
		f, err := s.readFrame()
		switch err {
		case nil:
		case mClient.ErrStatusNotFound:
			// we got a response from the map service but no data
			continue
		default:
			// rate limit spinning if client is offline, error returns immediately
			select {
			case <-s.HaltCh():
				return
			case <-time.After(retryDelay):
			}
			continue
		}

		// process Acks
		s.processAck(f)
		s.Lock()
		s.ReadBuf.Write(f.Payload)
		// signal that data has been read to callers blocking on Read()

		// If this is the last Frame in the stream, set RState to StreamClosed
		if f.Type == StreamEnd {
			s.RState = StreamClosed
		} else {
			s.ReadIdx += 1
		}
		s.Unlock()
		s.doOnRead()
	}
	s.Done()
}

// Read impl io.Reader
func (s *Stream) Read(p []byte) (n int, err error) {
	s.Lock()
	if s.RState == StreamClosed {
		s.Unlock()
		return 0, io.EOF
	}
	if s.WState == StreamClosed {
		s.Unlock()
		return 0, io.EOF
	}
	if s.ReadBuf.Len() == 0 {
		s.Unlock()
		select {
		case <-time.After(s.Timeout):
			return 0, os.ErrDeadlineExceeded
		case <-s.HaltCh():
			return 0, io.EOF
		case <-s.onRead:
			// frame has been read
		}
		s.Lock()
	}
	n, err = s.ReadBuf.Read(p)
	s.Unlock()
	// ignore io.EOF on short reads from ReadBuf
	if err == io.EOF {
		if n > 0 {
			return n, nil
		}
	}
	return n, err
}

// Write impl io.Writer
func (s *Stream) Write(p []byte) (n int, err error) {
	// writes message with our last read pointer as header
	s.Lock()
	// buffer data to bytes.Buffer
	if s.WState == StreamClosed || s.WState == StreamClosing {
		s.Unlock()
		return 0, io.EOF
	}
	// take MaxWriteBufSize as ... a guideline rather than a hard limit
	// because many users of io.Writer do not seem to handle short writes
	// properly, so just rate limit calls to write by waiting until
	// a frame has been transmitted before returning
	if s.WriteBuf.Len() >= s.MaxWriteBufSize {
		s.Unlock()
		select {
		case <-time.After(s.Timeout):
			return 0, os.ErrDeadlineExceeded
		case <-s.HaltCh():
			return 0, io.EOF
		case <-s.onStreamClose:
			return 0, io.EOF
		case <-s.onWrite:
		}
		s.Lock()
	}
	defer s.doFlush()
	defer s.Unlock()
	return s.WriteBuf.Write(p)
}

// Close terminates the Stream with a final Frame and blocks future Writes
func (s *Stream) Close() error {
	s.Lock()
	if s.WState == StreamOpen {
		s.WState = StreamClosing
		s.Unlock()
		s.doFlush()       // wake up a sleeping writer !
		<-s.onStreamClose // block until writer has finalized
		s.Lock()
		s.RState = StreamClosed
		s.Unlock()
		return nil
	}
	s.Unlock()
	return nil
}

func (s *Stream) writer() {
	for {

		select {
		case <-s.HaltCh():
			return
		default:
		}
		mustAck := false
		mustTeardown := false
		s.Lock()
		switch s.WState {
		case StreamClosed:
			s.onStreamClose <- struct{}{}
			s.Unlock()
			return
		case StreamOpen, StreamClosing:
			if s.ReadIdx-s.AckIdx >= s.WindowSize {
				mustAck = true
			}
			if s.RState == StreamClosed || s.WState == StreamClosing {
				mustTeardown = true
				if s.WriteBuf.Len() != 0 {
					mustTeardown = false
				}
				if s.ReadIdx-s.AckIdx > 0 {
					mustAck = true
				}
			}
			if !mustAck && !mustTeardown {
				s.R.Lock()
				// must wait for Ack before continuing to transmit
				mustWait := uint64(len(s.R.Wack)) >= s.WindowSize || s.WriteBuf.Len() == 0
				if s.WState == StreamClosing {
					mustWait = false
				}
				s.R.Unlock()
				if mustWait {
					s.Unlock()
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
		f.id = s.WriteIdx
		f.Ack = s.ReadIdx

		if mustTeardown {
			// final Ack and frame transmitted
			s.WState = StreamClosed
			f.Type = StreamEnd
		}
		f.Payload = make([]byte, FramePayloadSize)
		// Read up to the maximum frame payload size
		n, err := s.WriteBuf.Read(f.Payload)
		s.Unlock()
		switch err {
		case nil, io.ErrUnexpectedEOF, io.EOF:
		default:
		}
		f.Payload = f.Payload[:n]
		if n > 0 || mustAck || mustTeardown {
			err = s.txFrame(f)
			switch err {
			case nil:
			default:
				select {
				case <-s.HaltCh():
					return
				case <-time.After(retryDelay):
				}
				continue
			}
			// Signal that data has been written to callers blocked on Write due to
			// maximum write buffer size exceeded
			s.doOnWrite()
		}
	}
	s.Done()
}

// derive the reader frame ID for frame_num
func (s *Stream) rxFrameID(frame_num uint64) common.MessageID {
	f := make([]byte, 8)
	binary.BigEndian.PutUint64(f, frame_num)
	return H(append(s.ReadIDBase[:], f...))
}

func (s *Stream) rxFrameKey(frame_num uint64) *[keySize]byte {
	f := make([]byte, 8)
	binary.BigEndian.PutUint64(f, frame_num)
	hk := H(append(s.ReadKey[:], f...))
	k := [keySize]byte(hk)
	return &k
}

func (s *Stream) txFrameKey(frame_num uint64) *[keySize]byte {
	f := make([]byte, 8)
	binary.BigEndian.PutUint64(f, frame_num)
	hk := H(append(s.WriteKey[:], f...))
	k := [keySize]byte(hk)
	return &k
}

// derive the writer frame ID for frame_num
func (s *Stream) txFrameID(frame_num uint64) common.MessageID {
	f := make([]byte, 8)
	binary.BigEndian.PutUint64(f, frame_num)
	return H(append(s.WriteIDBase[:], f...))
}

func (s *Stream) txFrame(frame *Frame) (err error) {
	serialized, err := cbor.Marshal(frame)
	if err != nil {
		return err
	}
	_, _, til := epochtime.Now()
	s.Lock()
	// Retransmit unacknowledged blocks every few epochs
	m := &smsg{f: frame, priority: uint64(time.Now().Add(til + 2*epochtime.Period).UnixNano())}
	frame_id := s.txFrameID(frame.id)
	frame_key := s.txFrameKey(frame.id)
	// Update reference to last acknowledged message
	if frame.Ack > s.AckIdx {
		s.AckIdx = frame.Ack
	}
	s.Unlock()

	// zero extend ciphertext until maximum FramePayloadSize
	if FramePayloadSize-len(serialized) > 0 {
		padding := make([]byte, FramePayloadSize-len(serialized))
		serialized = append(serialized, padding...)
	}

	// use frame_id bytes as nonce
	nonce := [nonceSize]byte{}
	copy(nonce[:], frame_id[:nonceSize])
	ciphertext := secretbox.Seal(nil, serialized, &nonce, frame_key)
	err = s.c.Put(frame_id, ciphertext)
	if err != nil {
		return err
	}
	s.Lock()
	s.WriteIdx += 1
	s.Unlock()

	// Enable retransmissions of unacknowledged frames
	s.txEnqueue(m)
	return nil
}

func (s *Stream) txEnqueue(m *smsg) {
	// use a timerqueue here and set an acknowledgement retransmit timeout; ideally we would know the effective durability of the storage medium and maximize the retransmission delay so that we retransmit a message as little as possible.
	s.R.Lock()
	s.R.Wack[m.f.id] = struct{}{}
	s.R.Unlock()
	s.TQ.Push(m)
}

func H(i []byte) (res common.MessageID) {
	return common.MessageID(sha256.Sum256(i))
}

// produce keymaterial from handshake secrets
func (s *Stream) exchange(mysecret, othersecret []byte) {

	salt := []byte("stream_reader_writer_keymaterial")
	hash := sha256.New
	reader_keymaterial := hkdf.New(hash, othersecret[:], salt, nil)
	writer_keymaterial := hkdf.New(hash, mysecret[:], salt, nil)

	// obtain the frame encryption key and sequence seed
	_, err := io.ReadFull(writer_keymaterial, s.WriteKey[:])
	if err != nil {
		panic(err)
	}
	_, err = io.ReadFull(writer_keymaterial, s.WriteIDBase[:])
	if err != nil {
		panic(err)
	}

	// obtain the frame decryption key and sequence seed
	_, err = io.ReadFull(reader_keymaterial, s.ReadKey[:])
	if err != nil {
		panic(err)
	}
	_, err = io.ReadFull(reader_keymaterial, s.ReadIDBase[:])
	if err != nil {
		panic(err)
	}
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
	s.Lock()
	idx := s.ReadIdx
	s.Unlock()
	frame_id := s.rxFrameID(idx)
	fc := make(chan interface{}, 1)
	// s.c.Get() is a blocking call, so wrap in a goroutine so
	// we can select on s.HaltCh() and
	f := func() {
		ciphertext, err := s.c.Get(frame_id)
		if err != nil {
			fc <- err
			return
		} else {
			// use frame_id bytes as nonce
			nonce := [nonceSize]byte{}
			copy(nonce[:], frame_id[:nonceSize])
			plaintext, ok := secretbox.Open(nil, ciphertext, &nonce, s.rxFrameKey(idx))
			if !ok {
				// damaged Stream, abort / retry / fail ?
				// TODO: indicate serious error somehow
				fc <- errors.New("Failed to decrypt")
				return
			}
			f := new(Frame)
			f.id = idx
			err = cbor.Unmarshal(plaintext, f)
			if err != nil {
				// TODO: indicate serious error somehow
				fc <- err
				return
			}
			fc <- f
		}
	}
	s.Go(f)
	select {
	case f := <-fc:
		switch v := f.(type) {
		case *Frame:
			return v, nil
		case error:
			return nil, v
		default:
			panic("unknown type")
		}
	case <-s.HaltCh():
		return nil, errors.New("Halted")
	}
	panic("NotReached")
}

func (s *Stream) processAck(f *Frame) {
	ackD := false
	s.R.Lock()
	// ack all frames predecessor to peer ack
	for i, _ := range s.R.Wack {
		if i <= f.Ack {
			delete(s.R.Wack, i)
			ackD = true
		}
	}
	s.R.Unlock()
	// update last_ack from peer
	s.Lock()
	if f.Ack > s.PeerAckIdx {
		s.PeerAckIdx = f.Ack
	}
	s.Unlock()
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
	network, address string
}

// Network implements net.Addr
func (s *StreamAddr) Network() string {
	return s.network
}

// String implements net.Addr String()
func (s *StreamAddr) String() string {
	return s.address
}

// NewStream handshakes and starts the read/write workers
func NewStream(c *mClient.Client, mysecret, theirsecret []byte) *Stream {
	s := new(Stream)
	s.c = c
	s.RState = StreamOpen
	s.WState = StreamOpen
	s.Timeout = defaultTimeout
	// timerqueue calls s.Push when timeout of enqueued item
	s.R = &ReTx{s: s}
	s.R.Wack = make(map[uint64]struct{})
	s.TQ = client.NewTimerQueue(s.R)
	s.WriteBuf = new(bytes.Buffer)
	s.ReadBuf = new(bytes.Buffer)

	s.WriteKey = &[keySize]byte{}
	s.ReadKey = &[keySize]byte{}
	s.exchange(mysecret, theirsecret)
	s.Start()
	return s
}

// LoadStream initializes a Stream from state saved by Save()
func LoadStream(c *mClient.Client, state []byte) (*Stream, error) {
	s := new(Stream)
	s.c = c
	err := cbor.Unmarshal(state, s)
	if err != nil {
		return nil, err
	}
	s.R.s = s
	s.TQ.NextQ = s.R
	s.TQ.Timer = time.NewTimer(0)
	s.TQ.L = new(sync.Mutex)
	return s, nil
}

// Save serializes the current state of the Stream
func (s *Stream) Save() ([]byte, error) {
	s.Lock()
	s.R.Lock()
	defer s.Unlock()
	defer s.R.Unlock()
	return cbor.Marshal(s)
}

// Start starts the reader and writer workers
func (s *Stream) Start() {
	s.WindowSize = 7
	s.MaxWriteBufSize = 42 * FramePayloadSize
	s.onFlush = make(chan struct{}, 1)
	s.onAck = make(chan struct{}, 1)
	s.onStreamClose = make(chan struct{}, 1)
	s.onWrite = make(chan struct{}, 1)
	s.onRead = make(chan struct{}, 1)
	s.TQ.Start()
	s.Go(s.reader)
	s.Go(s.writer)
}

func init() {
	b, _ := cbor.Marshal(Frame{})
	cborFrameOverhead := len(b)
	nonce := [nonceSize]byte{}
	rand.Reader.Read(nonce[:])
	key := &[keySize]byte{}
	rand.Reader.Read(key[:])
	ciphertext := secretbox.Seal(nil, b, &nonce, key)
	secretboxOverhead := len(ciphertext) - len(b)
	FramePayloadSize = mClient.PayloadSize - cborFrameOverhead - secretboxOverhead
}

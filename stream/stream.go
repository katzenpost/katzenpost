package stream

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
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
	"sync"
	"time"
)

const (
	keySize   = 32
	nonceSize = 24
)

var (
	retryDelay       = epochtime.Period / 16
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

// TID returns the temporary storage ID for a MessageID
func TID(i common.MessageID) common.MessageID {
	pre := []byte("Both clients get this from somewhere to prepend the input to H, such as the PriorSharedRandom")
	return H(append(pre, i[:]...))
}

type Stream struct {
	sync.Mutex
	worker.Worker

	c *mClient.Client

	// frame encryption secrets
	writekey *[keySize]byte // secretbox key to encrypt with
	readkey  *[keySize]byte // secretbox key to decrypt with

	// read/write secrets initialized from handshake
	write_id_base common.MessageID
	read_id_base  common.MessageID

	// buffers
	writeBuf *bytes.Buffer // buffer to enqueue data before being transmitted
	readBuf  *bytes.Buffer // buffer to reassumble data from Frames

	// our frame pointers
	f_read_idx  uint64
	f_write_idx uint64

	// idx of last ack
	f_ack_idx uint64

	tq *client.TimerQueue
	r  *retx

	// Parameters
	// stream_window_size is the number of messages ahead of peer's
	// ackknowledgement that the writeworker will periodically retransmit
	stream_window_size uint64

	max_writebuf_size int

	// RState indicates Reader State
	RState StreamState

	// RState indicates Writer State
	WState StreamState

	// timeout value used internally before failing a blocking call
	defaultTimeout time.Duration

	// onFlush signals writer worker to wake and transmit frames
	onFlush       chan struct{}
	onAck         chan struct{}
	onWrite       chan struct{}
	onRead        chan struct{}
	onStreamClose chan struct{}
}

// glue for timerQ
type retx struct {
	sync.Mutex
	s    *Stream
	wack map[uint64]struct{}
}

// Push implements the client.nqueue interface
func (r *retx) Push(i client.Item) error {
	// time to retransmit a block that has not been acknowledged yet
	m, ok := i.(*smsg)
	if !ok {
		panic("must be smsg")
	}

	r.Lock()
	_, ok = r.wack[m.f.id]
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
		select {
		case <-s.HaltCh():
			return
		default:
		}

		s.Lock()
		switch s.RState {
		case StreamClosed:
			// No more frames will be sent by peer
			// If ReliableStream, send final Ack
			if s.f_read_idx > s.f_ack_idx {
				s.doFlush()
			}
			s.Unlock()
			return
		case StreamOpen:
			// prod writer to Ack
			if s.f_read_idx-s.f_ack_idx >= s.stream_window_size {
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
		s.readBuf.Write(f.Payload)
		// signal that data has been read to callers blocking on Read()

		// If this is the last Frame in the stream, set RState to StreamClosed
		if f.Type == StreamEnd {
			s.RState = StreamClosed
		} else {
			s.f_read_idx += 1
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
	if s.readBuf.Len() == 0 {
		s.Unlock()
		select {
		case <-time.After(s.defaultTimeout):
			return 0, io.EOF
		case <-s.HaltCh():
			return 0, io.EOF
		case <-s.onRead:
			// frame has been read
		}
		s.Lock()
	}
	n, err = s.readBuf.Read(p)
	s.Unlock()
	// ignore io.EOF on short reads from readBuf
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
	// take max_writebuf_size as ... a guideline rather than a hard limit
	// because many users of io.Writer do not seem to handle short writes
	// properly, so just rate limit calls to write by waiting until
	// a frame has been transmitted before returning
	if s.writeBuf.Len() >= s.max_writebuf_size {
		s.Unlock()
		select {
		case <-time.After(s.defaultTimeout):
			return 0, io.EOF
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
	return s.writeBuf.Write(p)
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
			if s.f_read_idx-s.f_ack_idx >= s.stream_window_size {
				mustAck = true
			}
			if s.RState == StreamClosed || s.WState == StreamClosing {
				mustTeardown = true
				if s.writeBuf.Len() != 0 {
					mustTeardown = false
				}
				if s.f_read_idx-s.f_ack_idx > 0 {
					mustAck = true
				}
			}
			if !mustAck && !mustTeardown {
				s.r.Lock()
				// must wait for Ack before continuing to transmit
				mustWait := uint64(len(s.r.wack)) >= s.stream_window_size || s.writeBuf.Len() == 0
				if s.WState == StreamClosing {
					mustWait = false
				}
				s.r.Unlock()
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
		f.id = s.f_write_idx
		f.Ack = s.f_read_idx

		if mustTeardown {
			// final Ack and frame transmitted
			s.WState = StreamClosed
			f.Type = StreamEnd
		}
		f.Payload = make([]byte, FramePayloadSize)
		// Read up to the maximum frame payload size
		n, err := s.writeBuf.Read(f.Payload)
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
	return H(append(s.read_id_base[:], f...))
}

func (s *Stream) rxFrameKey(frame_num uint64) *[keySize]byte {
	f := make([]byte, 8)
	binary.BigEndian.PutUint64(f, frame_num)
	hk := H(append(s.readkey[:], f...))
	k := [keySize]byte(hk)
	return &k
}

func (s *Stream) txFrameKey(frame_num uint64) *[keySize]byte {
	f := make([]byte, 8)
	binary.BigEndian.PutUint64(f, frame_num)
	hk := H(append(s.writekey[:], f...))
	k := [keySize]byte(hk)
	return &k
}

// derive the writer frame ID for frame_num
func (s *Stream) txFrameID(frame_num uint64) common.MessageID {
	f := make([]byte, 8)
	binary.BigEndian.PutUint64(f, frame_num)
	return H(append(s.write_id_base[:], f...))
}

func (s *Stream) txFrame(frame *Frame) (err error) {
	serialized, err := cbor.Marshal(frame)
	if err != nil {
		return err
	}
	_, _, til := epochtime.Now()
	s.Lock()
	// Retransmit unacknowledged blocks every few epochs
	m := &smsg{f: frame, priority: uint64(til + 2*epochtime.Period)}
	frame_id := s.txFrameID(frame.id)
	frame_key := s.txFrameKey(frame.id)
	// Update reference to last acknowledged message
	if frame.Ack > s.f_ack_idx {
		s.f_ack_idx = frame.Ack
	}
	s.Unlock()

	// encrypt serialized frame
	nonce := [nonceSize]byte{}
	_, err = rand.Reader.Read(nonce[:])
	if err != nil {
		return err
	}

	// zero extend ciphertext until maximum FramePayloadSize
	if FramePayloadSize-len(serialized) > 0 {
		padding := make([]byte, FramePayloadSize-len(serialized))
		serialized = append(serialized, padding...)
	}

	ciphertext := secretbox.Seal(nil, serialized, &nonce, frame_key)
	ciphertext = append(nonce[:], ciphertext...)

	err = s.c.Put(TID(frame_id), ciphertext)
	if err != nil {
		return err
	}
	s.Lock()
	s.f_write_idx += 1
	s.Unlock()

	// Enable retransmissions of unacknowledged frames
	s.txEnqueue(m)
	return nil
}

func (s *Stream) txEnqueue(m *smsg) {
	// use a timerqueue here and set an acknowledgement retransmit timeout; ideally we would know the effective durability of the storage medium and maximize the retransmission delay so that we retransmit a message as little as possible.
	s.r.Lock()
	s.r.wack[m.f.id] = struct{}{}
	s.r.Unlock()
	s.tq.Push(m)
}

func b64(id common.MessageID) string {
	return base64.StdEncoding.EncodeToString(id[:])
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
	_, err := io.ReadFull(writer_keymaterial, s.writekey[:])
	if err != nil {
		panic(err)
	}
	_, err = io.ReadFull(writer_keymaterial, s.write_id_base[:])
	if err != nil {
		panic(err)
	}

	// obtain the frame decryption key and sequence seed
	_, err = io.ReadFull(reader_keymaterial, s.readkey[:])
	if err != nil {
		panic(err)
	}
	_, err = io.ReadFull(reader_keymaterial, s.read_id_base[:])
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
	idx := s.f_read_idx
	s.Unlock()
	ciphertext, err := s.c.Get(TID(s.rxFrameID(idx)))
	if err != nil {
		return nil, err
	}
	nonce := [nonceSize]byte{}
	copy(nonce[:], ciphertext[:nonceSize])
	ciphertext = ciphertext[nonceSize:]
	plaintext, ok := secretbox.Open(nil, ciphertext, &nonce, s.rxFrameKey(idx))
	if !ok {
		// damaged Stream, abort / retry / fail ?
		// TODO: indicate serious error somehow
		panic("damaged Stream, decrypt fail")
		return nil, err
	}

	f := new(Frame)
	f.id = idx
	err = cbor.Unmarshal(plaintext, f)
	if err != nil {
		// XXX: corrupted stream must terminate
		// TODO: indicate serious error somehow
		panic("damaged Stream, incorrect Frame")
		return nil, err
	}
	return f, nil
}

func (s *Stream) processAck(f *Frame) {
	ackD := false
	s.r.Lock()
	// ack all frames predecessor to peer ack
	for i, _ := range s.r.wack {
		if i <= f.Ack {
			delete(s.r.wack, i)
			ackD = true
		}
	}
	s.r.Unlock()
	// prod writer() waiting on Ack
	if ackD {
		select {
		case s.onAck <- struct{}{}:
		default:
		}
	}
}

// impl net.Addr
type StreamAddr struct {
	network, address string
}

func (s *StreamAddr) Network() string {
	return s.network
}

func (s *StreamAddr) String() string {
	return s.address
}

// newstream handshakes and starts a read worker
func NewStream(c *mClient.Client, mysecret, theirsecret []byte) *Stream {
	s := new(Stream)
	s.c = c

	// what is a good size to balance message loss vs interactivity
	s.stream_window_size = 7
	s.max_writebuf_size = 42 * FramePayloadSize
	s.RState = StreamOpen
	s.WState = StreamOpen
	s.defaultTimeout = 5 * time.Minute
	// timerqueue calls s.Push when timeout of enqueued item
	s.r = &retx{s: s}
	s.r.wack = make(map[uint64]struct{})
	s.tq = client.NewTimerQueue(s.r)
	s.writeBuf = new(bytes.Buffer)
	s.readBuf = new(bytes.Buffer)

	s.writekey = &[keySize]byte{}
	s.readkey = &[keySize]byte{}
	s.exchange(mysecret, theirsecret)
	s.onFlush = make(chan struct{}, 1)
	s.onAck = make(chan struct{}, 1)
	s.onStreamClose = make(chan struct{}, 1)
	s.onWrite = make(chan struct{}, 1)
	s.onRead = make(chan struct{}, 1)
	s.Go(s.reader)
	s.Go(s.writer)
	return s
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
	FramePayloadSize = mClient.PayloadSize - nonceSize - cborFrameOverhead - secretboxOverhead
}

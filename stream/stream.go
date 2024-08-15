package stream

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"github.com/fxamacker/cbor/v2"
	"github.com/katzenpost/hpqc/rand"
	"github.com/katzenpost/katzenpost/client"
	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/worker"
	mClient "github.com/katzenpost/katzenpost/pigeonhole/client"
	"github.com/katzenpost/katzenpost/pigeonhole/common"
	"golang.org/x/crypto/hkdf"
	"golang.org/x/crypto/nacl/secretbox"
	"gopkg.in/op/go-logging.v1"
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
	hash               = sha256.New
	cborFrameOverhead  = 0
	retryDelay         = epochtime.Period / 16
	minBackoffDelay    = 1 * time.Millisecond
	maxBackoffDelay    = 200 * time.Millisecond // epochtime.Period
	defaultTimeout     = 5 * time.Minute
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
	l *sync.Mutex
	worker.Worker

	startOnce *sync.Once
	// address of the Stream
	Addr *StreamAddr

	// Initiator is true if Stream is created by NewStream or Listen methods
	Initiator bool
	log       *logging.Logger

	c Transport
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

// ReTx implmements client.nqueue and re-transmits unacknowledged frames
type ReTx struct {
	sync.Mutex
	s    *Stream
	Wack map[uint64]struct{}
}

// Push is called by the TimerQueue (Stream.TQ) with a client.Item when its deadline expires.
func (r *ReTx) Push(i client.Item) error {
	// time to retransmit a block that has not been acknowledged yet
	m, ok := i.(*smsg)
	if !ok {
		panic("must be smsg")
	}

	r.Lock()
	_, ok = r.Wack[m.f.Id]
	r.Unlock()
	if !ok {
		// Already Acknowledged
		return nil
	}
	// XXX: causes panic in TimerQueue if an error is returned
	err := r.s.txFrame(m.f)
	if err != nil {
		// try again later
		m.priority = uint64(time.Now().Add(retryDelay).UnixNano())
		r.s.txEnqueue(m)
	}
	return nil
}

// reader polls receive window of messages and adds to the reader queue
func (s *Stream) reader() {
	backoff := minBackoffDelay
	for {
		s.l.Lock()
		switch s.RState {
		case StreamClosed:
			// No more frames will be sent by peer
			// If ReliableStream, send final Ack
			if s.ReadIdx > 0 {
				if s.ReadIdx-1 > s.AckIdx {
					s.log.Debugf("reader mustAck at StreamClosed() doFlush()")
					s.doFlush()
				}
			}
			s.l.Unlock()
			s.doFlush()
			return
		case StreamOpen:
			// prod writer to Ack
			if s.ReadIdx-s.AckIdx > s.WindowSize {
				s.log.Debugf("reader() doFlush: s.ReadIdx-s.AckIdx = %d", s.ReadIdx-s.AckIdx)
				s.doFlush()
			}
		}
		s.l.Unlock()

		// read next frame
		f, err := s.readFrame()
		switch err {
		case nil:
			backoff = backoff / 4
			if backoff < minBackoffDelay {
				backoff = minBackoffDelay
			}
			s.log.Debugf("reader() got Frame: resetting backoff: %s", backoff)
		case mClient.ErrStatusNotFound:
			s.log.Debugf("%s for frame: %d", err, s.ReadIdx)
			backoff = backoff << 1
			if backoff > maxBackoffDelay {
				backoff = maxBackoffDelay
			}
			s.log.Debugf("reader() backoff: wait for %s", backoff)
			// we got a response from the pigeonhole service but no data
			select {
			case <-time.After(backoff):
			case <-s.HaltCh():
				return
			}
			continue
		default:
			s.log.Errorf("readFrame Got err %s", err)
			s.log.Errorf("retrying in %s", backoff)
			backoff = backoff << 1
			if backoff > maxBackoffDelay {
				backoff = maxBackoffDelay
			}
			// rate limit spinning if client is offline, error returns immediately
			select {
			case <-s.HaltCh():
				return
			case <-time.After(backoff):
			}
			continue
		}

		// process Acks
		s.processAck(f)
		s.l.Lock()
		n, _ := s.ReadBuf.Write(f.Payload)

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

// Read impl io.Reader
func (s *Stream) Read(p []byte) (n int, err error) {
	s.l.Lock()
	if s.ReadBuf.Len() == 0 {
		if s.RState == StreamClosed {
			s.l.Unlock()
			return 0, io.EOF
		}
		s.log.Debugf("Read() sleeping until unblocked")
		s.l.Unlock()
		select {
		case <-time.After(s.Timeout):
			return 0, os.ErrDeadlineExceeded
		case <-s.HaltCh():
			return 0, io.EOF
		case <-s.onRead:
			// awaken on StreamData or StreamEnd
		}
		s.l.Lock()
	}
	n, err = s.ReadBuf.Read(p)
	s.l.Unlock()
	// ignore io.EOF on short reads from ReadBuf
	if err == io.EOF {
		if s.RState != StreamClosed || n > 0 {
			return n, nil
		}
	}
	return n, err
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
	// take MaxWriteBufSize as ... a guideline rather than a hard limit
	// because many users of io.Writer do not seem to handle short writes
	// properly, so just rate limit calls to write by waiting until
	// a frame has been transmitted before returning
	if s.WriteBuf.Len() >= s.MaxWriteBufSize {
		s.l.Unlock()
		select {
		case <-time.After(s.Timeout):
			return 0, os.ErrDeadlineExceeded
		case <-s.HaltCh():
			return 0, io.EOF
		case <-s.onWrite:
		}
		s.l.Lock()
	}
	defer s.l.Unlock()
	// if stream closed, abort Write
	if s.WState == StreamClosed || s.WState == StreamClosing {
		<-s.onStreamClose
		return 0, io.EOF
	}
	s.log.Debugf("Write() doFlush()")
	defer s.doFlush()
	return s.WriteBuf.Write(p)
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
		select {
		case <-s.onWrite:
		case <-s.HaltCh():
			return ErrHalted
		}
		s.l.Lock()
		if s.WriteBuf.Len() == 0 {
			s.l.Unlock()
			return nil
		}
		s.l.Unlock()
	}
}

// Close terminates the Stream with a final Frame and blocks future Writes
// it does *not* drain WriteBuf, call Sync() to flush WriteBuf first.
func (s *Stream) Close() error {
	s.l.Lock()
	if s.WState == StreamOpen {
		s.WState = StreamClosing
		s.l.Unlock()
		s.log.Debugf("Close() doFlush()")
		s.doFlush()       // wake up a sleeping writer !
		<-s.onStreamClose // block until writer has finalized
		return nil
	}
	s.l.Unlock()
	return nil
}

func (s *Stream) writer() {
	for {

		s.log.Debugf("writer() top of loop")
		select {
		case <-s.HaltCh():
			return
		default:
		}
		mustAck := false
		mustWaitForAck := false
		mustTeardown := false
		s.l.Lock()
		switch s.WState {
		case StreamClosed:
			s.log.Debugf("writer() StreamClosed")
			close(s.onStreamClose)
			s.l.Unlock()
			return
		case StreamOpen, StreamClosing:
			if s.WState == StreamOpen {
				s.log.Debugf("writer() StreamOpen")
			} else {
				s.log.Debugf("writer() StreamClosing")
			}
			if s.ReadIdx-s.AckIdx > s.WindowSize {
				s.log.Debugf("writer() WindowSize: mustAck")
				mustAck = true
			}
			if s.RState == StreamClosed || s.WState == StreamClosing {
				mustTeardown = true
				if s.WState != StreamClosing {
					s.log.Debugf("Rstate == StreamClosed, setting WState == StreamClosing")
					s.WState = StreamClosing
				}
				if s.ReadIdx-s.AckIdx > 1 {
					mustAck = true
				}
			}
			if !mustAck && !mustTeardown {
				s.R.Lock()

				// must wait for Ack before continuing to transmit
				if s.WriteIdx > s.PeerAckIdx+s.WindowSize {
					mustWaitForAck = true
					s.log.Debugf("mustWaitForAck: s.WriteIdx - PeerAckIdx : %d > %d", int(s.WriteIdx)-int(s.PeerAckIdx), s.WindowSize)
				}
				mustWaitForData := s.WriteBuf.Len() == 0
				if mustWaitForData {
					s.log.Debugf("mustWaitForData")
				}
				mustWait := mustWaitForAck || mustWaitForData
				if s.WState == StreamClosing {
					s.log.Debugf("writer() StreamClosing !mustWait")
					mustWait = false
				}
				s.R.Unlock()
				if mustWait {
					s.log.Debugf("writer() sleeping")
					s.l.Unlock()
					select {
					case <-s.onFlush:
						s.log.Debugf("writer() woke onFlush")
					case <-s.onAck:
						s.log.Debugf("writer() woke onAck")
					case <-s.HaltCh():
						s.log.Debugf("writer() Halt()")
						return
					}
					continue // re-evaluate all of the conditions above after wakeup!
				}
			}
		}

		f := new(Frame)
		s.log.Debugf("Sending frame for %d", s.WriteIdx)
		f.Id = s.WriteIdx

		if s.ReadIdx == 0 {
			// have not read any data from peer yet so Ack = 0 is special case
			f.Ack = 0
		} else {
			f.Ack = s.ReadIdx - 1 // ReadIdx points at next frame, which we haven't read
		}

		if mustTeardown {
			// final Ack and frame transmitted
			s.log.Debugf("Setting WState.StreamClosed and StreamEnd")
			s.WState = StreamClosed
			f.Type = StreamEnd
		}
		f.Payload = make([]byte, s.PayloadSize)
		// Read up to the maximum frame payload size
		n, err := s.WriteBuf.Read(f.Payload)
		s.l.Unlock()
		switch err {
		case nil, io.ErrUnexpectedEOF, io.EOF:
		default:
		}
		f.Payload = f.Payload[:n]
		if n > 0 || mustAck || mustTeardown {
			s.log.Debugf("txFrame on condition:")
			if mustAck {
				s.log.Debugf("mustAck")
			}
			if mustTeardown {
				s.log.Debugf("mustTeardown")
			}
			if n > 0 {
				s.log.Debugf("n>0")
			} else {
				s.log.Debugf("n==0")
			}
			err = s.txFrame(f)
			switch err {
			case nil:
				s.log.Debugf("txFrame OK: do.OnWrite()")
				// wakes writer into state where Write returns 0, nil
				// which is treated as EOF condition
				if n > 0 {
					s.doOnWrite()
				} else {
					// do not wake blocked Write() if no data frames were sent
				}
			default:
				s.log.Debugf("txFrame err: do.OnWrite()")
				select {
				case <-s.HaltCh():
					return
				case <-time.After(retryDelay):
					s.log.Debugf("txFrame err: after retryDelay")
				}
				continue
			}
		}
	}
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
	//_, _, til := epochtime.Now()
	s.l.Lock()
	// Retransmit unacknowledged blocks every few epochs
	//m := &smsg{f: frame, priority: uint64(time.Now().Add(til + 2*epochtime.Period).UnixNano())}
	m := &smsg{f: frame, priority: uint64(time.Now().Add(10 * time.Second).UnixNano())}
	frame_id := s.txFrameID(frame.Id)
	frame_key := s.txFrameKey(frame.Id)
	// Update reference to last acknowledged message on retransmit
	if s.ReadIdx > 0 {
		// update retransmitted frame to point at last read payload (ReadIdx points at next frame)
		frame.Ack = s.ReadIdx - 1
	}
	s.l.Unlock()

	// zero extend ciphertext until maximum PayloadSize
	if s.PayloadSize-len(serialized) > 0 {
		padding := make([]byte, s.PayloadSize-len(serialized))
		serialized = append(serialized, padding...)
	}

	// use frame_id bytes as nonce
	nonce := [nonceSize]byte{}
	copy(nonce[:], frame_id[:nonceSize])
	ciphertext := secretbox.Seal(nil, serialized, &nonce, frame_key)
	err = s.c.Put(frame_id[:], ciphertext)
	if err != nil {
		s.log.Debugf("txFrame: Put() failed with %s", err)
		// reschedule packet for transmission after retryDelay
		// rather than 2 * epochtime.Period
		newPriority := uint64(time.Now().Add(retryDelay).UnixNano())
		s.log.Debugf("txFrame: setting priority to %s for retry", time.Unix(0, int64(newPriority)))
		m.priority = newPriority
	}
	s.l.Lock()
	s.txEnqueue(m)
	if frame.Id == s.WriteIdx {
		// do not increment WriteIdx unless frame tx'd is tip
		s.WriteIdx += 1
	}
	s.AckIdx = frame.Ack
	s.l.Unlock()
	return err
}

func (s *Stream) txEnqueue(m *smsg) {
	// use a timerqueue here and set an acknowledgement retransmit timeout; ideally we would know the effective durability of the storage medium and maximize the retransmission delay so that we retransmit a message as little as possible.
	s.R.Lock()
	s.R.Wack[m.f.Id] = struct{}{}
	s.R.Unlock()
	s.TQ.Push(m)
}

func H(i []byte) (res common.MessageID) {
	return common.MessageID(sha256.Sum256(i))
}

// Dial returns a Stream initialized with secret address
func Dial(c Transport, network, addr string) (*Stream, error) {
	s := newStream(c)
	a := &StreamAddr{network: network, address: addr}
	err := s.keyAsDialer(a)
	if err != nil {
		return nil, err
	}
	s.Start()
	return s, nil
}

// configure keymaterial as dialer from a shared secret
func (s *Stream) keyAsDialer(addr *StreamAddr) error {
	listenerSecret, dialerSecret, err := deriveListenerDialerSecrets(addr.String())
	if err != nil {
		return err
	}
	s.Addr = addr
	s.Initiator = false
	salt := []byte("stream_reader_writer_keymaterial")
	reader_keymaterial := hkdf.New(hash, listenerSecret[:], salt, nil)
	writer_keymaterial := hkdf.New(hash, dialerSecret[:], salt, nil)

	// obtain the frame encryption key and sequence seed
	_, err = io.ReadFull(writer_keymaterial, s.WriteKey[:])
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
	return nil
}

// generate a new address secret to Listen() or Dial() with
func generate() string {
	newsecret := &[keySize]byte{}
	_, err := io.ReadFull(rand.Reader, newsecret[:])
	if err != nil {
		panic(err)
	}
	return base64.StdEncoding.EncodeToString(newsecret[:])
}

// convert base64 string into tuple of secrets for reader/writer
func deriveListenerDialerSecrets(addr string) ([]byte, []byte, error) {
	// get base secret
	secret, err := base64.StdEncoding.DecodeString(addr)
	if err != nil {
		return nil, nil, err
	}
	if len(secret) < keySize {
		return nil, nil, ErrInvalidAddr
	}
	salt := []byte("stream_reader_writer_keymaterial")
	keymaterial := hkdf.New(hash, secret, salt, nil)
	listenerSecret := &[keySize]byte{}
	dialerSecret := &[keySize]byte{}
	_, err = io.ReadFull(keymaterial, listenerSecret[:])
	if err != nil {
		panic(err)
	}
	_, err = io.ReadFull(keymaterial, dialerSecret[:])
	if err != nil {
		panic(err)
	}
	return listenerSecret[:], dialerSecret[:], nil
}

// Listen should be net.Listener
func Listen(c Transport, network string, addr *StreamAddr) (*Stream, error) {
	s := newStream(c)
	err := s.keyAsListener(addr)
	if err != nil {
		return nil, err
	}
	s.Start()
	return s, nil
}

// configure keymaterial as dialer from a shared secret
func (s *Stream) keyAsListener(addr *StreamAddr) error {
	listenerSecret, dialerSecret, err := deriveListenerDialerSecrets(addr.String())
	if err != nil {
		return err
	}
	s.Addr = addr
	s.Initiator = true
	salt := []byte("stream_reader_writer_keymaterial")
	reader_keymaterial := hkdf.New(hash, dialerSecret[:], salt, nil)
	writer_keymaterial := hkdf.New(hash, listenerSecret[:], salt, nil)

	// obtain the frame encryption key and sequence seed
	_, err = io.ReadFull(writer_keymaterial, s.WriteKey[:])
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
	return nil
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
	s.l.Unlock()
	frame_id := s.rxFrameID(idx)
	fc := make(chan interface{}, 1)
	// s.c.Get() is a blocking call, so wrap in a goroutine so
	// we can select on s.HaltCh() and
	f := func() {
		ciphertext, err := s.c.Get(frame_id[:])
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
				fc <- ErrFrameDecrypt
				return
			}
			f := new(Frame)
			f.Id = idx
			_, err = cbor.UnmarshalFirst(plaintext, f)
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
		return nil, ErrHalted
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
	s.l.Lock()
	if f.Ack > s.PeerAckIdx {
		s.log.Debugf("Got Ack %d > PeerAckIdx: %d", f.Ack, s.PeerAckIdx)
		s.PeerAckIdx = f.Ack
	}
	s.l.Unlock()
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

// LocalAddr implements net.Addr LocalAddr()
func (s *Stream) LocalAddr() *StreamAddr {
	return s.Addr
}

// LocalAddr implements net.Conn RemoteAddr()
func (s *Stream) RemoteAddr() *StreamAddr {
	return s.Addr
}

// Transport describes the interface to Get or Put Frames
type Transport mClient.ReadWriteClient

func newStream(c Transport) *Stream {
	s := new(Stream)
	s.c = c
	s.PayloadSize = PayloadSize(c)
	s.l = new(sync.Mutex)
	s.startOnce = new(sync.Once)
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
	return s
}

// NewStream generates a new address and starts the read/write workers
// func NewStream(c Transport, identity sign.PrivateKey, sign.PublicKey) *Stream {
func NewStream(s *client.Session) *Stream {
	c, _ := mClient.NewClient(s)
	addr := &StreamAddr{network: "", address: generate()}
	t := mClient.DuplexFromSeed(c, true, []byte(addr.String()))
	st := newStream(t)
	st.log = s.GetLogger(fmt.Sprintf("Stream %p", st))
	err := st.keyAsListener(addr)
	if err != nil {
		panic(err)
	}
	st.Start()
	return st
}

// LoadStream initializes a Stream from state saved by Save()
func LoadStream(s *client.Session, state []byte) (*Stream, error) {
	st := new(Stream)
	st.l = new(sync.Mutex)
	st.log = s.GetLogger(fmt.Sprintf("Stream %p", st))
	st.startOnce = new(sync.Once)
	_, err := cbor.UnmarshalFirst(state, st)
	if err != nil {
		return nil, err
	}
	c, _ := mClient.NewClient(s)
	st.c = mClient.DuplexFromSeed(c, st.Initiator, []byte(st.LocalAddr().String()))

	// Ensure that the frame geometry cannot change an active stream
	// FIXME: Streams should support resetting sender/receivers on Geometry changes.
	if st.PayloadSize != PayloadSize(st.c) {
		panic(ErrGeometryChanged)
	}

	st.R.s = st
	st.TQ.NextQ = st.R
	st.TQ.Timer = time.NewTimer(0)
	st.TQ.L = new(sync.Mutex)
	return st, nil
}

// Save serializes the current state of the Stream
func (s *Stream) Save() ([]byte, error) {
	s.l.Lock()
	s.R.Lock()
	defer s.l.Unlock()
	defer s.R.Unlock()
	return cbor.Marshal(s)
}

// Start starts the reader and writer workers
func (s *Stream) Start() {
	s.startOnce.Do(func() {
		s.WindowSize = 7
		s.MaxWriteBufSize = int(s.WindowSize)
		s.onFlush = make(chan struct{}, 1)
		s.onAck = make(chan struct{}, 1)
		s.onStreamClose = make(chan struct{}, 1)
		s.onWrite = make(chan struct{}, 1)
		s.onRead = make(chan struct{})
		s.TQ.Start()
		s.Go(s.reader)
		s.Go(s.writer)
	})
}

// DialDuplex returns a stream using capability backed pigeonhole storage (Duplex)
func DialDuplex(s *client.Session, network, addr string) (*Stream, error) {
	c, err := mClient.NewClient(s)
	if err != nil {
		return nil, err
	}
	t := mClient.DuplexFromSeed(c, false, []byte(addr))
	st := newStream(t)
	a := &StreamAddr{network: network, address: addr}
	st.log = s.GetLogger(fmt.Sprintf("Stream %p", st))
	st.log.Debugf("DialDuplex: DuplexFromSeed: %x", []byte(a.String()))

	err = st.keyAsDialer(a)
	if err != nil {
		return nil, err
	}
	st.Start()
	return st, nil
}

// ListenDuplex returns a Stream using capability pigeonhole storage (Duplex) as initiator
func ListenDuplex(s *client.Session, network, addr string) (*Stream, error) {
	c, _ := mClient.NewClient(s)
	st := newStream(mClient.DuplexFromSeed(c, true, []byte(addr)))
	a := &StreamAddr{network: network, address: addr}
	st.log = s.GetLogger(fmt.Sprintf("Stream %p", st))
	st.log.Debugf("ListenDuplex: DuplexFromSeed: %x", []byte(a.String()))
	err := st.keyAsListener(a)
	if err != nil {
		return nil, err
	}
	st.Start()
	return st, nil
}

// NewDuplex returns a Stream using capability pigeonhole storage (Duplex) a Listener
func NewDuplex(s *client.Session) (*Stream, error) {
	c, err := mClient.NewClient(s)
	if err != nil {
		return nil, err
	}
	a := &StreamAddr{network: "", address: generate()}
	st := newStream(mClient.DuplexFromSeed(c, true, []byte(a.String())))
	st.log = s.GetLogger(fmt.Sprintf("Stream %p", st))
	err = st.keyAsListener(a)
	if err != nil {
		return nil, err
	}
	st.Start()
	return st, nil
}

func init() {
	b, _ := cbor.Marshal(Frame{})
	cborFrameOverhead = len(b)
}

func PayloadSize(c Transport) int {
	return c.PayloadSize() - cborFrameOverhead - secretbox.Overhead - nonceSize
}

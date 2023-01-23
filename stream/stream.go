package client

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
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
)

const (
	keySize   = 32
	nonceSize = 24
)

var (
	FramePayloadSize int
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

// StreamMode indicates the type of Stream
type StreamMode uint8

const (
	// ReliableStream transmits StreamWindowSize Frames ahead of Ack
	ReliableStream StreamMode = iota
	// ScrambleStream transmits Frames in any order without retransmissions
	ScrambleStream
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

	// counters
	f_writes uint64 // number of frames written
	f_reads  uint64 // number of frames read

	// our frame pointers
	f_read_idx  uint64
	f_write_idx uint64

	// peer's frame pointers
	peer_read_idx  uint64
	peer_write_idx uint64

	tq *client.TimerQueue
	r  *retx

	// Parameters
	// stream_window_size is the number of messages ahead of peer's
	// ackknowledgement that the writeworker will periodically retransmit
	stream_window_size uint

	// Mode indicates whether this Stream will be a fire-and-forget ScrambleStream or a reliable channel with retranmissions of unacknowledged messages
	Mode StreamMode

	// doFlush signals writer worker to wake and transmit frames
	doFlush chan struct{}
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
		// next is the MessageID of the next message in the stream
		s.Lock()
		id := s.f_read_idx
		frame_id := s.rxFrameID(id)
		frame_key := s.rxFrameKey(id)
		s.f_reads += 1
		s.Unlock()
		ciphertext, err := s.c.Get(TID(frame_id))
		if err == nil {
			nonce := [nonceSize]byte{}
			copy(nonce[:], ciphertext[:nonceSize])
			ciphertext = ciphertext[nonceSize:]
			plaintext, ok := secretbox.Open(nil, ciphertext, &nonce, frame_key)
			if !ok {
				// damaged Stream, abort / retry / fail ?
				panic("damaged Stream, decrypt fail")
			}

			f := new(Frame)
			f.id = id
			err := cbor.Unmarshal(plaintext, f)
			if err != nil {
				// XXX: corrupted stream must terminate
				panic("damaged Stream, incorrect Frame")
			}

			// remove acknowledged Frames from waiting-ack
			s.r.Lock()
			// ack all frames predecessor to peer ack
			for i, _ := range s.r.wack {
				if i < f.Ack {
					delete(s.r.wack, i)
				}
			}
			s.r.Unlock()
			s.Lock()

			// write payload to buf
			s.readBuf.Write(f.Payload)

			// increment the frame pointer
			// increment the read pointer
			s.f_read_idx += 1
			s.Unlock()
		}
	}
}

// Read impl io.Reader
func (s *Stream) Read(p []byte) (n int, err error) {
	s.Lock()
	defer s.Unlock()
	n, err = s.readBuf.Read(p)
	if err == io.EOF {
		// XXX: was final Frame and stream Closed ?
		return n, nil
	}
	return
}

// Write impl io.Writer
func (s *Stream) Write(p []byte) (n int, err error) {
	// writes message with our last read pointer as header
	s.Lock()
	// buffer data to bytes.Buffer
	s.writeBuf.Write(p)
	s.Unlock()
	// flush writer
	s.doFlush <- struct{}{}
	return len(p), nil
}

func (s *Stream) writer() {
	for {
		select {
		case <-s.HaltCh():
			return
		default:
		}
		f := new(Frame)
		// indicate how much of the complete stream we've read
		s.Lock()
		if s.Mode == ReliableStream {
			f.Ack = s.f_read_idx
		}
		f.Payload = make([]byte, FramePayloadSize)
		// Read up to the maximum frame payload size
		n, err := s.writeBuf.Read(f.Payload)
		f.id = s.f_write_idx
		s.Unlock()
		switch err {
		case nil, io.ErrUnexpectedEOF, io.EOF:
		default:
		}
		if n > 0 {
			// truncate frame.Payload
			f.Payload = f.Payload[:n]
			err = s.txFrame(f)
			if err != nil {
				/*
				s.Lock()
				s.State = StreamClosed
				s.Unlock()
				*/
				return
			}
			s.Lock()
			s.f_write_idx += 1
			s.Unlock()
		} else {
			select {
			case <-s.doFlush:
			case <-s.HaltCh():
				return
			}
		}
	}
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
	// Enable retransmissions of unacknowledged frames
	if s.Mode == ReliableStream {
		s.txEnqueue(m)
	}

	return nil
}

func (s *Stream) txEnqueue(m *smsg) {
	// use a timerqueue here and set an acknowledgement retransmit timeout; ideally we would know the effective durability of the storage medium and maximize the retransmission delay so that we retransmit a message as little as possible.
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

// newstream handshakes and starts a read worker
func NewStream(c *mClient.Client, mysecret, theirsecret []byte) *Stream {
	s := new(Stream)
	s.c = c
	s.Mode = ReliableStream
	// timerqueue calls s.Push when timeout of enqueued item
	s.r = &retx{s: s}
	s.tq = client.NewTimerQueue(s.r)
	s.writeBuf = new(bytes.Buffer)
	s.readBuf = new(bytes.Buffer)

	s.writekey = &[keySize]byte{}
	s.readkey = &[keySize]byte{}
	s.exchange(mysecret, theirsecret)
	s.doFlush = make(chan struct{}, 1)
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

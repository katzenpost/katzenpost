package client

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"github.com/fxamacker/cbor/v2"
	"github.com/katzenpost/katzenpost/client"
	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/worker"
	"github.com/katzenpost/katzenpost/map/common"
	"io"
	"sync"
	"time"
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
	Type    FrameType
	Ack     common.MessageID // acknowledgement of last seen msg
	Payload []byte           // transported data
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
	mid      common.MessageID // message unique id used to derive message storage location (NOT TID)
	f        *Frame           // payload of message
	priority uint64           // timeout, for when to retransmit if the message is not acknowledged
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

	c *Client

	// XXX: need a type for the agreed key and direction as output of handshake
	asecret  string           // our secret
	bsecret  string           // peers secret
	writePtr common.MessageID // our write pointer (tip)
	readPtr  common.MessageID // our read pointer
	peerAck  common.MessageID // peer's last ack
	writeBuf *bytes.Buffer    // buffer to enqueue data before being transmitted
	readBuf  *bytes.Buffer    // buffer to reassumble data from Frames

	frame_written uint               // number of frames written
	frame_read    uint               // numbr of frames read
	tq            *client.TimerQueue // a delay queue to enable retransmissions of unacknowledged blocks
	r             *retx

	// Parameters
	// stream_window_size is the number of messages ahead of peer's
	// ackknowledgement that the writeworker will periodically retransmit

	stream_window_size uint
	// Mode indicates whether this Stream will be a fire-and-forget ScrambleStream or a reliable channel with retranmissions of unacknowledged messages
	Mode    StreamMode
	doFlush chan struct{}
}

// XXX: need to calculate the CBOR overhead of serializing frame
// to figure out what the maximum message size should be per block stored
var maxmsg = 1000

// glue for timerQ
type retx struct {
	sync.Mutex
	c    *Client                     // XXX pointer to stream or client??
	wack map[common.MessageID]uint64 // waiting for ack until priority (uint64)
}

// Push implements the client.nqueue interface
func (r *retx) Push(i client.Item) error {
	// time to retransmit a block that has not been acknowledged yet
	m, ok := i.(*smsg)
	if !ok {
		panic("must be smsg")
	}

	if _, ok := r.wack[m.mid]; !ok {
		// not waiting ack, do not retransmit
		return nil
	}

	// update the priority and re-enqueue for retransmission
	m.priority = uint64(time.Now().Add(4 * time.Hour).Unix())
	r.Lock() // XXX: protect wack
	defer r.Unlock()
	r.wack[m.mid] = m.priority // update waiting ack map

	// XXX: encrypt payload before transmit
	b, err := cbor.Marshal(m.f)
	if err != nil {
		return err
	}

	return r.c.Put(TID(m.mid), b)
}

// reader polls receive window of messages and adds to the reader queue
func (s *Stream) reader() {

	for {
		// next is the MessageID of the next message in the stream
		msg, err := s.c.Get(TID(s.readPtr))
		if err == nil {
			// XXX: decrypt block
			f := new(Frame)
			err := cbor.Unmarshal(msg, f)
			if err != nil {
				// XXX: corrupted stream must terminate
				return
			}

			// remove acknowledged Frames from waiting-ack
			s.Lock()
			_, ok := s.r.wack[f.Ack]
			if ok {
				delete(s.r.wack, f.Ack)
			}

			// write payload to buf
			s.readBuf.Write(f.Payload)

			// increment the read pointer
			s.readPtr = H(s.readPtr[:])
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
		// XXX: support disabled Acks
		f := &Frame{Ack: s.readPtr, Payload: make([]byte, maxmsg)}
		s.Lock()
		// Read up to the maximum frame payload size
		n, err := s.writeBuf.Read(f.Payload)
		s.Unlock()
		switch err {
		case nil, io.ErrUnexpectedEOF, io.EOF:
		default:
		}
		if n > 0 {
			// truncate frame.Payload
			f.Payload = f.Payload[:n]
			s.txFrame(f)
		} else {
			select {
			case <-s.doFlush:
			case <-s.HaltCh():
				return
			}
		}
	}
}

func (s *Stream) txFrame(f *Frame) (err error) {
	// XXX: FIXME: retransmit unack'd on next storage rotation/epoch ??
	// Retransmit unacknowledged blocks every few epochs
	_, _, til := epochtime.Now()
	m := &smsg{mid: s.writePtr, f: f, priority: uint64(til + 2*epochtime.Period)}

	// XXX: encrypt frame before storing
	b, err := cbor.Marshal(f)
	if err != nil {
		return err
	}

	err = s.c.Put(TID(m.mid), b)
	if err != nil {
		return err
	}

	s.txEnqueue(m)

	// XXX: this is just hashing again, not deriving location from sequence
	s.writePtr = H(s.writePtr[:])

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

// take order two secrets, a > b
func (s *Stream) exchange(mysecret, othersecret string) {
	s.asecret = mysecret
	s.bsecret = othersecret
}

// newstream handshakes and starts a read worker
func NewStream(c *Client, mysecret, theirsecret string) *Stream {
	s := new(Stream)
	s.c = c
	// timerqueue calls s.Push when timeout of enqueued item
	s.r = &retx{c: c}
	s.tq = client.NewTimerQueue(s.r)
	s.writeBuf = new(bytes.Buffer)
	s.readBuf = new(bytes.Buffer)
	s.exchange(mysecret, theirsecret)
	s.writePtr = H([]byte(mysecret + theirsecret + "one")) // derive starting ID for writing
	s.readPtr = H([]byte(theirsecret + mysecret + "one"))  // dervice starting ID for reading
	s.doFlush = make(chan struct{}, 1)
	go s.Go(s.reader)
	go s.Go(s.writer)
	return s
}

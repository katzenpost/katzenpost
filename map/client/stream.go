package client

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/fxamacker/cbor/v2"
	"github.com/katzenpost/katzenpost/client"
	"github.com/katzenpost/katzenpost/map/common"
	"sync"
	"time"
)

// payload of ctframe is frame
type frame struct {
	Ack     common.MessageID // acknowledgement of last seen msg
	Payload []byte           // transported data
}

// smsg is some sort of container for written messages pending acknowledgement
type smsg struct {
	mid      common.MessageID // message unique id used to derive message storage location
	msg      []byte           // payload of message
	priority uint64           // timeout, for when to retransmit if the message is not acknowledged
}

// Priority implements client.Item interface; used by TimerQueue for retransmissions
func (s *smsg) Priority() uint64 {
	return s.priority
}

type stream struct {
	sync.Mutex
	c        *Client
	asecret  string             // our secret
	bsecret  string             // peers secret
	writePtr common.MessageID   // our write pointer (tip)
	readPtr  common.MessageID   // our read pointer
	peerAck  common.MessageID   // peer's last ack
	buf      *bytes.Buffer      // buffer to facilitate io.ReadWriter
	tq       *client.TimerQueue // a delay queue to enable retransmissions
	r        *retx

	// tunable parameters
	// stream retransmit window size
	// how many messages we can write ahead before acknowledgement
	//
	// stream acknowldgement permits dropping messages from the retransmit queue
}

var maxmsg = 1000

// fetch
func fetch(storageid string) (*smsg, error) {
	panic("NotImplemented")
	return nil, nil
}

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

	// update the priority and re-enqueue for retransmission
	m.priority = uint64(time.Now().Add(4 * time.Hour).Unix())
	r.Lock() // XXX: protect wack
	defer r.Unlock()
	r.wack[m.mid] = m.priority // update waiting ack map
	return r.c.Put(m.mid, m.msg)
}

// readworker loop polls receive window of messages and adds to the reader queue
func (s *stream) readworker() {

	for {
		// scheduler baked-in fetch()
		// nextblock
		// next is the MessageID of the next message in the stream
		msg, err := s.c.Get(s.reader())
		if err == nil {
			// XXX: decrypt block
			// deserialize cbor to frame
			// update stream pointers
			// append bytes to stream
			// XXX: decode smsgs, update our view of receiver ptr
			// XXX: pick serialization for smsgs? cbor
			// pick block encryption key derivation scheme - ...
			// from here we can drop messages from the retransmit queue once they have been acknowledged
			f := new(frame)
			err := cbor.Unmarshal(msg, f)
			if err != nil {
				panic(err)
				continue
				// XXX alert user to failures???
			}

			// a write has been ack'd
			// remove from the waiting-ack list
			// and do not retransmit any more
			_, ok := s.r.wack[f.Ack]
			if ok {
				fmt.Printf("Deleting ack'd msgid %s from w(aiting)ack", b64(f.Ack))
				delete(s.r.wack, f.Ack)
			}

			fmt.Printf("Writing %s to buf\n", f.Payload)
			// write payload to buf
			s.buf.Write(f.Payload)

			// increment the read pointer
			fmt.Printf("Updating readPtr!: %s -> ", b64(s.readPtr))
			s.readPtr = H(s.readPtr[:])
			fmt.Printf("%s\n", b64(s.readPtr))
		} else {
			fmt.Printf("Woah, got an error fetching %s: %s\n", b64(s.readPtr), err)
			<-time.After(1 * time.Second)
		}
	}
}

// Read impl io.Reader
func (s *stream) Read(p []byte) (n int, err error) {
	return s.buf.Read(p)
}

// Write impl io.Writer
func (s *stream) Write(p []byte) (n int, err error) {
	// writes message with our last read pointer as header
	if len(p) > maxmsg {
		return 0, errors.New("Message Too large")
	}
	var msg []byte

	if len(p) > maxmsg {
		n = maxmsg
		msg = p[:maxmsg]
	} else {
		msg = p
	}

	// FIXME: retransmit unack'd on next storage rotation/epoch ??
	m := &smsg{mid: s.writer(), msg: msg, priority: uint64(time.Now().Add(4 * time.Hour).Unix())}

	// enqueue transmitted messages
	// periodically retransmit messages that have not been acknowledged, e.g. using a timer + exponential backoff

	s.txEnqueue(m)

	// serialize msg into a frame
	f := &frame{Ack: s.readPtr, Payload: msg}
	b, err := cbor.Marshal(f)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Putting: %s %s\n", m.msg, base64.StdEncoding.EncodeToString(m.mid[:]))
	s.c.Put(m.mid, b)

	if err != nil {
		return 0, err
	}

	// this is just hashing again, not deriving location from sequence
	fmt.Printf("Updating writePtr!: %s -> ", b64(s.writePtr))
	s.writePtr = H(s.writePtr[:])
	fmt.Printf("%s\n", b64(s.writePtr))

	return len(msg), nil
}

func (s *stream) txEnqueue(m *smsg) {
	// use a timerqueue here and set an acknowledgement retransmit timeout; ideally we would know the effective durability of the storage medium and maximize the retransmission delay so that we retransmit a message as little as possible.
	s.tq.Push(m)
}

func H(i string) (res common.MessageID) {
	return common.MessageID(sha256.Sum256([]byte(i)))
}

// take secret and return writer order
func (s *stream) writer() common.MessageID {
	// do whatever else with sharedrandom etc
	fmt.Printf("writer(): %s\n", b64(s.writePtr))
	return s.writePtr
}

// take secret and return reader order
// XXX: needs to figure out how A, B are differentiated; our secret construction should include our order relative to the peer; e.g. we need to agree who goes first in the hash function

// secret is composed of my secret + your secret
// and I'll construct my view of the read and write sequences in that way
// so the secret exchange consists simply of exchanging 2 secrets, not 1

func (s *stream) reader() common.MessageID {
	// XXX: do whatever to dervice tid
	fmt.Printf("reader(): %s\n", b64(s.readPtr))
	return s.readPtr
}

// take order two secrets, a > b
func (s *stream) exchange(mysecret, othersecret string) {
	s.asecret = mysecret
	s.bsecret = othersecret
}

// newstream handshakes and starts a read worker
func NewStream(c *Client, mysecret, theirsecret string) *stream {
	s := &stream{}
	s.c = c
	// timerqueue calls s.Push when timeout of enqueued item
	s.r = &retx{c: c}
	s.tq = client.NewTimerQueue(s.r)
	s.buf = new(bytes.Buffer)
	s.exchange(mysecret, theirsecret)
	s.writePtr = H([]byte(mysecret + theirsecret + "one")) // derive starting ID for writing
	s.readPtr = H([]byte(theirsecret + mysecret + "one"))  // dervice starting ID for reading
	go s.readworker()                                      // XXX: streams never die
	return s
}

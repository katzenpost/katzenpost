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
	Pab     common.MessageID
	Payload []byte // transported data
}

type smsg struct {
	mid      common.MessageID // message unique id used to derive message storage location
	pab      common.MessageID // acknowledgement of last known peer message
	msg      []byte           // payload of message
	priority uint64           // timeout, for when to retransmit if the message is not acknowledged
}

// Priority implements client.Item interface; used by TimerQueue for retransmissions
func (s *smsg) Priority() uint64 {
	return s.priority
}

type stream struct {
	c       *Client
	asecret string             // our secret
	bsecret string             // peers secret
	pab     common.MessageID   // our write pointer
	pba     common.MessageID   // peer's read pointer (sent via acknowledgement)
	buf     *bytes.Buffer      // buffer to facilitate io.ReadWriter
	tq      *client.TimerQueue // a delay queue to enable retransmissions
	r       *retx

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

			// pab has been acknowledged, stop
			// periodic retransmission and clean map
			pr, ok := s.r.wack[f.Pab]
			if ok {
				s.tq.Remove(&smsg{priority: pr})
				delete(s.r.wack, f.Pab)
			}

			fmt.Printf("Writing %s to buf\n", f.Payload)
			// write payload to buf
			s.buf.Write(f.Payload)

			// increment the read pointer
			fmt.Printf("Updating pab!: %s -> ", base64.StdEncoding.EncodeToString(s.pba[:]))
			s.pba = common.MessageID(sha256.Sum256(s.pba[:]))
			fmt.Printf("%s\n", base64.StdEncoding.EncodeToString(s.pba[:]))
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

	m := &smsg{mid: s.writer(), pab: s.pab, msg: msg, priority: uint64(time.Now().Add(4 * time.Hour).Unix())}

	// enqueue transmitted messages
	// periodically retransmit messages that have not been acknowledged, e.g. using a timer + exponential backoff

	s.txEnqueue(m)

	// serialize msg into a frame
	f := &frame{Pab: s.pab, Payload: msg}
	b, err := cbor.Marshal(f)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Putting: %s %s\n", m.msg, base64.StdEncoding.EncodeToString(m.mid[:]))
	s.c.Put(m.mid, b)

	if err != nil {
		return 0, err
	}

	s.pab = common.MessageID(sha256.Sum256(s.pab[:]))
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
	write := H(s.asecret + s.bsecret + string(s.pab[:]))
	fmt.Printf("writer(): %s\n", base64.StdEncoding.EncodeToString(write[:]))
	return write
}

// take secret and return reader order
// XXX: needs to figure out how A, B are differentiated; our secret construction should include our order relative to the peer; e.g. we need to agree who goes first in the hash function

// secret is composed of my secret + your secret
// and I'll construct my view of the read and write sequences in that way
// so the secret exchange consists simply of exchanging 2 secrets, not 1

func (s *stream) reader() common.MessageID {
	read := H(s.bsecret + s.asecret + string(s.pba[:]))
	fmt.Printf("reader(): %s\n", base64.StdEncoding.EncodeToString(read[:]))
	return read
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
	s.pba = H(mysecret + theirsecret + "one") // pick initial pba
	s.pab = H(theirsecret + mysecret + "one") // pick initial pab
	go s.readworker()                         // XXX: streams never die
	return s
}

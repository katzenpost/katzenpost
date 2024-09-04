package stream

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net/http"
	_ "net/http/pprof"
	"runtime"
	"sync"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/katzenpost/hpqc/rand"
	"github.com/katzenpost/katzenpost/core/log"
	"github.com/stretchr/testify/require"
)

var numEntries = 42
var logBackend *log.Backend

type mockTransport struct {
	l    *sync.Mutex
	data map[string][]byte
}

type lossyMockTransport struct {
	mockTransport
	lossRate float64
}

func NewLossyMockTransport(lossRate float64) Transport {
	m := lossyMockTransport{lossRate: lossRate}
	m.l = new(sync.Mutex)
	m.l.Lock()
	defer m.l.Unlock()
	m.data = make(map[string][]byte)
	return m
}

func (m lossyMockTransport) Put(addr []byte, payload []byte) error {
	// probabalistically fail to put messages
	if m.lossRate < 0 || m.lossRate > 1 {
		panic("lossRate must be >=0 < 1")
	}
	rate := int(m.lossRate * 100)
	l := rand.NewMath().Intn(100)
	if l > rate {
		m.l.Lock()
		defer m.l.Unlock()
		m.data[string(addr)] = payload
	}
	return nil
}

// newStreams returns an initialized pair of Streams
func newStreams(t Transport) (*Stream, *Stream) {

	a := newStream(t)
	a.log = logBackend.GetLogger(fmt.Sprintf("Stream %p", a))
	addr := &StreamAddr{address: generate()}
	a.keyAsListener(addr)
	b := newStream(t)
	b.log = logBackend.GetLogger(fmt.Sprintf("Stream %p", b))
	b.keyAsDialer(addr)

	if a == nil || b == nil {
		panic("newStream returned nil")
	}
	return a, b
}

func NewMockTransport() Transport {
	m := &mockTransport{}
	m.l = new(sync.Mutex)
	m.l.Lock()
	defer m.l.Unlock()
	m.data = make(map[string][]byte)
	return m
}

func (m mockTransport) Put(addr []byte, payload []byte) error {
	m.l.Lock()
	defer m.l.Unlock()
	m.data[string(addr)] = payload
	return nil
}

func (m mockTransport) Get(addr []byte) ([]byte, error) {
	m.l.Lock()
	defer m.l.Unlock()
	d, ok := m.data[string(addr)]
	if !ok {
		return nil, errors.New("NotFound")
	}
	return d, nil
}

func (m mockTransport) PayloadSize() int {
	return 1024
}

func randPayload() []byte {
	l := rand.NewMath().Intn(1 << 16)
	buf := make([]byte, l)
	io.ReadFull(rand.Reader, buf)
	for i := 0; i < l; i++ {
		buf[i] = 0x42
	}
	return buf
}

func TestMockTransport(t *testing.T) {
	garbage := NewMockTransport()
	wg := new(sync.WaitGroup)
	wg.Add(2)
	go func() {
		addr := make([]byte, 8)
		for i := 0; i < 4096; i++ {
			binary.BigEndian.PutUint64(addr, uint64(i))
			garbage.Put(addr, randPayload())
		}
		wg.Done()
	}()
	go func() {
		addr := make([]byte, 8)
		for i := 0; i < 4096; i++ {
			binary.BigEndian.PutUint64(addr, uint64(i))
			garbage.Put(addr, randPayload())
		}
		wg.Done()
	}()
	wg.Wait()
}

type msg struct {
	Num     int
	Name    string
	Payload []byte
}

func TestBufferedStream(t *testing.T) {
	require := require.New(t)
	trans := NewMockTransport()
	a, b := newStreams(trans)
	a.Start()
	b.Start()

	sent := make([]*msg, 0)
	recv := make([]*msg, 0)
	enc := cbor.NewEncoder(a)
	wg := new(sync.WaitGroup)
	wg.Add(2)
	// write data to receiver
	go func() {
		for i := 0; i < numEntries; i++ {
			hello := &msg{Num: i, Name: "Tester", Payload: randPayload()}
			sent = append(sent, hello)
			err := enc.Encode(hello)
			require.NoError(err)
			t.Logf("sent data %d", i)
		}
		//a.Close() // XXX: Stream.WriteBuf isn't drained yet!
		wg.Done()
	}()
	bs := BufferedStream{Stream: b}
	// read data
	go func() {
		for i := 0; i < numEntries; i++ {
			r := new(msg)
			err := bs.CBORDecode(r)
			if err == io.EOF {
				require.Equal(i, numEntries-1)
				break
			}
			require.NoError(err)
			recv = append(recv, r)
			t.Logf("recv data %d", i)
		}
		b.Close()
		wg.Done()
	}()
	wg.Wait()
	require.Equal(len(sent), len(recv))
	for i := 0; i < numEntries; i++ {
		require.Equal(sent[i], recv[i])
	}
}

func TestLossyStream(t *testing.T) {
	require := require.New(t)
	trans := NewLossyMockTransport(0.1)
	a, b := newStreams(trans)
	a.Start()
	b.Start()

	sent := make([]*msg, 0)
	recv := make([]*msg, 0)
	enc := cbor.NewEncoder(a)
	wg := new(sync.WaitGroup)
	wg.Add(2)
	// write data to receiver
	go func() {
		for i := 0; i < numEntries; i++ {
			hello := &msg{Num: i, Name: "Tester", Payload: make([]byte, 1024)}
			sent = append(sent, hello)
			err := enc.Encode(hello)
			require.NoError(err)
			t.Logf("sent data %d", i)
		}
		//a.Close() // XXX: Stream.WriteBuf isn't drained yet!
		wg.Done()
	}()
	bs := BufferedStream{Stream: b}
	// read data
	go func() {
		for i := 0; i < numEntries; i++ {
			r := new(msg)
			err := bs.CBORDecode(r)
			if err == io.EOF {
				require.Equal(i, numEntries-1)
				break
			}
			require.NoError(err)
			recv = append(recv, r)
			t.Logf("recv data %d", i)
		}
		b.Close()
		wg.Done()
	}()
	wg.Wait()
	require.Equal(len(sent), len(recv))
	for i := 0; i < numEntries; i++ {
		require.Equal(sent[i], recv[i])
	}
}

func init() {
	var e error
	logBackend, e = log.New("", "DEBUG", false)
	if e != nil {
		panic(e)
	}

	go func() {
		http.ListenAndServe("localhost:8181", nil)
	}()
	runtime.SetMutexProfileFraction(1)
	runtime.SetBlockProfileRate(1)
}

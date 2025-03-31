package stream

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net/http"
	_ "net/http/pprof"
	"runtime"
	"sync"
	"testing"
	"time"

	"github.com/fxamacker/cbor/v2"
	"github.com/katzenpost/hpqc/rand"
	"github.com/katzenpost/hpqc/bacap"
	"github.com/stretchr/testify/require"
)

var numEntries = 10

type message struct {
	payload []byte
	signature [64]byte
}

type mockTransport struct {
	l    *sync.Mutex
	data map[[32]byte]message
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
	m.data = make(map[[32]byte]message)
	return m
}

func (m lossyMockTransport) Put(ctx context.Context, addr [32]byte, sig [64]byte, payload []byte) error {
	// probabalistically fail to put messages
	if m.lossRate < 0 || m.lossRate > 1 {
		panic("lossRate must be >=0 < 1")
	}
	rate := int(m.lossRate * 100)
	l := rand.NewMath().Intn(100)
	if l > rate {
		m.l.Lock()
		defer m.l.Unlock()
		m.data[addr] = message{signature:sig, payload:payload}
	}
	return nil
}

// newStreams returns an initialized pair of Streams
func newStreams(t Transport) (*Stream, *Stream) {
	// create a pair of Streams that correspond to each end
	w1, err := bacap.NewBoxOwnerCap(rand.Reader)
	if err != nil {
		panic(err)
	}

	w2, err := bacap.NewBoxOwnerCap(rand.Reader)
	if err != nil {
		panic(err)
	}

	r1 := w1.UniversalReadCap()
	r2 := w1.UniversalReadCap()

	streamCtx := [32]byte{}
	_, err = io.ReadFull(rand.Reader, streamCtx[:])
	if err != nil {
		panic(err)
	}

	a := NewStream(t, w1, r2, streamCtx[:])
	b := NewStream(t, w2, r1, streamCtx[:])
	a.Start()
	b.Start()

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
	m.data = make(map[[32]byte]message)
	return m
}

func (m mockTransport) Put(ctx context.Context, addr [32]byte, sig [64]byte, payload []byte) error {
	m.l.Lock()
	defer m.l.Unlock()
	m.data[addr] = message{signature:sig, payload:payload}
	return nil
}

func (m mockTransport) Get(ctx context.Context, addr [32]byte) ([]byte, [64]byte, error) {
	m.l.Lock()
	d, ok := m.data[addr]
	m.l.Unlock()
	if !ok {
		<-time.After(2 * time.Second)
		return nil, [64]byte{}, errors.New("NotFound")
	}
	return d.payload, d.signature, nil
}

func (m mockTransport) PayloadSize() int {
	return 1024
}

func randPayload() []byte {
	l := rand.NewMath().Intn(1 << 12)
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
		addr := [32]byte{}
		for i := 0; i < 4096; i++ {
			binary.BigEndian.PutUint64(addr[:], uint64(i))
			garbage.Put(nil, addr, [64]byte{}, randPayload())
		}
		wg.Done()
	}()
	go func() {
		addr := [32]byte{}
		for i := 0; i < 4096; i++ {
			binary.BigEndian.PutUint64(addr[:8], uint64(i))
			garbage.Put(nil, addr, [64]byte{}, randPayload())
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
			enc.Encode(hello)
			t.Logf("sent data %d", i)
		}
		a.Sync()
		a.Close() // XXX: Stream.WriteBuf isn't drained yet!
		wg.Done()
	}()
	bs := BufferedStream{Stream: b}
	bs.Start()
	// read data
	go func() {
		for i := 0; i < numEntries; i++ {
			r := new(msg)
			err := bs.CBORDecode(r)
			if err == io.EOF {
				t.Logf("got EOF, done")
				break
			}
			recv = append(recv, r)
			t.Logf("recv data %d", i)
		}
		bs.Close()
		wg.Done()
	}()
	wg.Wait()
	a.Halt()
	bs.Halt()

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
		a.Sync()
		a.Close()
		wg.Done()
	}()
	bs := BufferedStream{Stream: b}
	bs.Start()
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
	a.Halt()
	b.Halt()
}

func init() {
	go func() {
		http.ListenAndServe("localhost:8282", nil)
	}()
	runtime.SetMutexProfileFraction(1)
	runtime.SetBlockProfileRate(1)
}

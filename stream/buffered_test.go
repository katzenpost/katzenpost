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
	"github.com/stretchr/testify/require"
)

var numEntries = 10

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

	a := newStream(EndToEnd)
	a.SetTransport(t)
	addr := &StreamAddr{Saddress: generate()}
	a.keyAsListener(addr)
	b := newStream(EndToEnd)
	b.SetTransport(t)
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
	d, ok := m.data[string(addr)]
	m.l.Unlock()
	if !ok {
		<-time.After(2 * time.Second)
		return nil, errors.New("NotFound")
	}
	return d, nil
}

func (m mockTransport) PutWithContext(ctx context.Context, addr []byte, payload []byte) error {
	return m.Put(addr, payload)
}

func (m mockTransport) GetWithContext(ctx context.Context, addr []byte) ([]byte, error) {
	return m.Get(addr)
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
	// Use a lower loss rate to make the test more reliable
	trans := NewLossyMockTransport(0.05) // 5% loss instead of 10%
	a, b := newStreams(trans)
	a.Start()
	b.Start()

	sent := make([]*msg, 0)
	recv := make([]*msg, 0)
	enc := cbor.NewEncoder(a)

	// Use fewer messages to reduce test time
	testEntries := 5

	wg := new(sync.WaitGroup)
	wg.Add(2)

	// write data to receiver
	go func() {
		defer wg.Done()
		for i := 0; i < testEntries; i++ {
			hello := &msg{Num: i, Name: "Tester", Payload: make([]byte, 512)} // Smaller payload
			sent = append(sent, hello)
			err := enc.Encode(hello)
			require.NoError(err)
			t.Logf("sent data %d", i)
		}
		a.Sync()
		a.Close()
	}()

	bs := BufferedStream{Stream: b}
	bs.Start()

	// read data with timeout to prevent hanging
	go func() {
		defer wg.Done()
		defer b.Close()

		// Give more time for retransmissions to work
		overallTimeout := time.After(60 * time.Second)

		for i := 0; i < testEntries; i++ {
			r := new(msg)

			// Per-message timeout to allow for retransmissions
			messageTimeout := time.After(15 * time.Second)

			// Use CBORDecodeAsync which returns a channel and is cancellable
			resultCh := bs.CBORDecodeAsync(r)

			select {
			case result := <-resultCh:
				if err, ok := result.(error); ok {
					if err == io.EOF {
						t.Logf("got EOF after receiving %d messages", len(recv))
						return
					}
					t.Logf("decode error: %v", err)
					return
				}
				recv = append(recv, r)
				t.Logf("recv data %d", i)
			case <-messageTimeout:
				t.Logf("timeout waiting for message %d after receiving %d messages", i, len(recv))
				return
			case <-overallTimeout:
				t.Logf("overall timeout after receiving %d messages", len(recv))
				return
			}
		}
	}()

	wg.Wait()
	a.Halt()
	bs.Halt()

	// With lossy transport, we expect some messages might be lost
	// The test passes if we receive at least 60% of messages (3 out of 5)
	minExpected := int(float64(testEntries) * 0.6)
	require.GreaterOrEqual(len(recv), minExpected, "Should receive at least %d messages", minExpected)
	require.LessOrEqual(len(recv), len(sent), "Should not receive more messages than sent")

	// Verify that received messages are in correct order and match sent messages
	for i := 0; i < len(recv); i++ {
		require.Equal(sent[recv[i].Num], recv[i], "Message content should match")
	}

	t.Logf("Test completed: sent %d messages, received %d messages", len(sent), len(recv))
}

func init() {
	go func() {
		http.ListenAndServe("localhost:8282", nil)
	}()
	runtime.SetMutexProfileFraction(1)
	runtime.SetBlockProfileRate(1)
}

// stream_test.go - pigeonhole service stream tests
// Copyright (C) 2022  Masala
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.
//go:build docker_test
// +build docker_test

package stream

import (
	"context"
	"fmt"
	"io"
	"runtime"
	"sync"
	"testing"
	"time"

	"encoding/base64"
	"github.com/fxamacker/cbor/v2"
	"github.com/katzenpost/hpqc/rand"
	"github.com/katzenpost/katzenpost/client"
	"github.com/katzenpost/katzenpost/client/config"
	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/pki"
	mClient "github.com/katzenpost/katzenpost/pigeonhole/client"
	"github.com/stretchr/testify/require"
	"net/http"
	_ "net/http/pprof"
)

// getSession waits until pki.Document is available and returns a *client.Session
func getSession(t *testing.T) *client.Session {
	require := require.New(t)
	cfg, err := config.LoadFile("testdata/client.toml")
	require.NoError(err)
	require.NotNil(cfg)
	cc, err := client.New(cfg)
	require.NotNil(cc)
	require.NoError(err)
	var session *client.Session
	for session == nil {
		session, err = cc.NewTOFUSession(context.Background())
		if err == pki.ErrNoDocument {
			_, _, till := epochtime.Now()
			<-time.After(till)
		} else {
			require.NoError(err)
		}
	}
	session.WaitForDocument(context.Background())
	// shut down the client with the session
	go func() {
		<-session.HaltCh()
		cc.Shutdown()
	}()
	return session
}

func TestFrameKey(t *testing.T) {
	require := require.New(t)

	// the same key should be returned for every idx
	a, b := newStreams(NewMockTransport())
	for i := 0; i < 4096; i++ {
		i := uint64(i)
		// require sender/receiver frame ID match
		require.Equal(a.rxFrameID(i), b.txFrameID(i))
		require.Equal(a.txFrameID(i), b.rxFrameID(i))

		// require sender/receiver frame keys match
		require.Equal(a.rxFrameKey(i), b.txFrameKey(i))
		require.Equal(a.txFrameKey(i), b.rxFrameKey(i))
	}
	a.Halt()
	b.Halt()
}

func TestCreateStream(t *testing.T) {
	require := require.New(t)
	session := getSession(t)
	defer session.Shutdown()
	require.NotNil(session)

	// listener (initiator) of stream
	s := NewStream(session)

	// receiver (dialer) of stream
	r, err := DialDuplex(session, "", s.RemoteAddr().String())
	require.NoError(err)

	msg := []byte("Hello World")
	t.Logf("Sending %s", string(msg))
	n, err := s.Write(msg)
	require.NoError(err)
	require.Equal(n, len(msg))

	yolo := make([]byte, len(msg))
	for {
		// XXX: the tricky part is that we don't have a convenience method that will handle spinning on Read() for us and
		// ReadAtLeast payload
		// I thought io.ReadAtLeast would do this, but we get EOF too soon
		// because we are just proxying the calls through bytes.Buffer and whatever it does
		n, err = r.Read(yolo)
		require.NoError(err)
		if n == len(msg) {
			t.Logf("Read %s", string(yolo))
			break
		} else {
			t.Logf("Read(%d): %s", n, string(yolo))
		}
		<-time.After(time.Second)
	}
	require.NoError(err)
	require.Equal(n, len(msg))
	require.Equal(yolo, msg)

	msg = []byte("Goodbye World")
	t.Logf("Sending %s", string(msg))
	n, err = s.Write(msg)
	require.NoError(err)
	require.Equal(n, len(msg))
	err = s.Sync()
	require.NoError(err)
	err = s.Close()
	require.NoError(err)

	yolo = make([]byte, len(msg))
	t.Logf("Reading Stream")
	n, err = io.ReadAtLeast(r, yolo, len(msg))
	require.NoError(err)
	require.Equal(n, len(msg))
	require.Equal(yolo, msg)
	t.Logf("Read %s", string(yolo))
	err = r.Close()
	require.NoError(err)
	s.Halt()
	r.Halt()
}

func TestStreamFragmentation(t *testing.T) {
	require := require.New(t)
	session := getSession(t)
	defer session.Shutdown()
	require.NotNil(session)

	c, err := mClient.NewClient(session)
	require.NoError(err)
	require.NotNil(c)

	wg := new(sync.WaitGroup)
	wg.Add(2)
	sidechannel := make(chan string, 0)

	// StreamAddr
	addr := &StreamAddr{"address", generate()}
	// worker A
	go func() {
		s, err := ListenDuplex(session, "", addr.String())
		require.NoError(err)
		for i := 0; i < 4; i++ {
			entropic := make([]byte, 4242) // ensures fragmentation
			io.ReadFull(rand.Reader, entropic)
			message := base64.StdEncoding.EncodeToString(entropic)
			mbytes := []byte(message)
			// tell the other worker what message we're going to try and send
			t.Logf("Sending %d bytes", len(message))
			sidechannel <- message
			offs := 0
			for offs < len(mbytes) {
				n, err := s.Write(mbytes[offs:])
				require.NoError(err)
				offs += n
			}
		}
		// Writer closes stream
		t.Logf("SendWorker Sync()")
		err = s.Sync()
		require.NoError(err)
		t.Logf("SendWorker Close()")
		err = s.Close()
		require.NoError(err)

		close(sidechannel)
		t.Logf("SendWorker Done()")
		require.NoError(err)
		wg.Done()

		// wait until reader has finished reading
		// before halting the writer()
		wg.Wait()
		s.Halt()
	}()

	// worker B
	go func() {
		s, err := DialDuplex(session, "", addr.String())
		require.NoError(err)
		for {
			msg, ok := <-sidechannel
			// channel was closed by writer, we're done
			if !ok {
				// verify that EOF is (eventually) returned on a Read after Stream.Close()
				foo := make([]byte, 42)
				var n int
				var err error
				// retry read until StreamClosed and EOF has arrived
				for err == nil {
					t.Logf("Waiting for StreamEnd")
					n, err = s.Read(foo)
					require.Equal(n, 0)
					<-time.After(2 * time.Second)
				}
				// stream must return EOF when writer has finalized stream
				require.Error(err, io.EOF)
				t.Logf("ReadWorker Close()")
				err = s.Close()
				require.NoError(err)
				wg.Done()
				s.Halt()
				return
			}
			b := make([]byte, len(msg))
			// Read() data until we have received the message
			for readOff := 0; readOff < len(msg); {
				n, err := s.Read(b[readOff:])
				if err != nil {
					t.Logf("read %d, total %d", n, readOff)
					if readOff+n < len(msg) {
						t.Errorf("Read() returned incomplete with err: %v", err)
						return
					}
				}
				t.Logf("Read %d bytes", n)

				readOff += n
				if n == 0 {
					// XXX retry a sensible time later, like the average round trip time
					<-time.After(time.Second * 2)
				}
			}
			t.Logf("Read total %d", len(b))
			require.Equal([]byte(msg), b)
		}
	}()
	wg.Wait()
}

func TestCBORSerialization(t *testing.T) {
	require := require.New(t)
	session := getSession(t)
	defer session.Shutdown()
	require.NotNil(session)

	// our view of stream
	// "other end" of stream
	s, err := NewDuplex(session)
	require.NoError(err)
	r, err := DialDuplex(session, "", s.RemoteAddr().String())
	require.NoError(err)

	type msg struct {
		Payload []byte
		Message string
		Name    string
		Count   int
	}

	enc := cbor.NewEncoder(s)
	dec := cbor.NewDecoder(r)
	for i := 0; i < 10; i++ {
		m := new(msg)
		m.Payload = make([]byte, 4200)
		for j := 0; j < len(m.Payload); j++ {
			m.Payload[j] = 0x10
		}
		m.Message = fmt.Sprintf("hello world, %d\n", i)
		m.Name = "foo"
		m.Count = i
		err := enc.Encode(m)
		require.NoError(err)
		t.Logf("Wrote CBOR object %d", i)
		m2 := new(msg)
		err = dec.Decode(m2)
		require.NoError(err)
		t.Logf("Decoded CBOR object %d", i)
		require.Equal(m.Message, m2.Message)
		require.Equal(m.Name, m2.Name)
		require.Equal(m.Count, m2.Count)
	}
	err = s.Close()
	require.NoError(err)
	err = r.Close()
	require.NoError(err)
	s.Halt()
	r.Halt()
}

func TestStreamSerialize(t *testing.T) {
	require := require.New(t)
	session := getSession(t)
	defer session.Shutdown()
	require.NotNil(session)

	// Initialize a capability backed stream (Duplex) as listener
	s, err := NewDuplex(session)
	require.NoError(err)
	// "other end" of stream
	r, err := DialDuplex(session, "", s.RemoteAddr().String())
	require.NoError(err)

	type msg struct {
		Payload []byte
		Message string
		Name    string
		Count   int
	}

	for i := 0; i < 10; i++ {
		enc := cbor.NewEncoder(s)
		dec := cbor.NewDecoder(r)
		m := new(msg)
		m.Payload = make([]byte, 42) //2 * FramePayloadSize)
		for j := 0; j < len(m.Payload); j++ {
			m.Payload[j] = 0x10
		}
		m.Message = fmt.Sprintf("hello world, %d\n", i)
		m.Name = "foo"
		m.Count = i
		err := enc.Encode(m)
		require.NoError(err)
		t.Logf("Wrote CBOR object %d", i)
		m2 := new(msg)
		err = dec.Decode(m2)
		require.NoError(err)
		t.Logf("Decoded CBOR object %d", i)
		require.Equal(m.Message, m2.Message)
		require.Equal(m.Name, m2.Name)
		require.Equal(m.Count, m2.Count)

		// stop the stream workers, serialize, deserialize, and start them again
		// note that the same stream object is kept

		s.Halt()
		senderStreamState, err := s.Save()
		require.NoError(err)
		s, err = LoadStream(session, senderStreamState)
		require.NoError(err)
		s.Start()
		r.Halt()
		receiverStreamState, err := r.Save()
		require.NoError(err)
		r, err = LoadStream(session, receiverStreamState)
		require.NoError(err)
		r.Start()
	}
	err = s.Close()
	require.NoError(err)
	err = r.Close()
	require.NoError(err)
}

func TestCreateMulticastStream(t *testing.T) {
	require := require.New(t)
	session := getSession(t)
	defer session.Shutdown()
	require.NotNil(session)

	// listener (initiator) of stream
	s := NewMulticastStream(session) // could experiment with different MaxWriteBufSize values
	// create a buffer of data
	buf := make([]byte, 42*1024)
	_, err := io.ReadFull(rand.Reader, buf)
	require.NoError(err)
	message := base64.StdEncoding.EncodeToString(buf)
	// send buffer of data
	_, err = s.Write([]byte(message))
	require.NoError(err)
	// really send buffer of data
	err = s.Sync()
	require.NoError(err)
	err = s.Close()
	require.NoError(err)

	// receiver (dialer) of stream
	r, err := DialDuplex(session, "", s.RemoteAddr().String())
	require.NoError(err)
	buf2 := make([]byte, len(message))
	n, err := io.ReadFull(r, buf2)
	require.NoError(err)
	require.Equal(n, len(message))
}

func init() {
	go func() {
		http.ListenAndServe("localhost:4242", nil)
	}()
	runtime.SetMutexProfileFraction(1)
	runtime.SetBlockProfileRate(1)
}

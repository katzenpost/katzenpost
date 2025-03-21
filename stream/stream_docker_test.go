// stream_docker_test.go - stream docker tests
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
	"bytes"
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
	n, err = io.ReadFull(r, yolo)
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
	// Generate StreamAddr
	addr := &StreamAddr{"address", generate()}

	// Listen and Dial the StreamAddr
	listener, err := ListenDuplex(session, "", addr.String())
	require.NoError(err)

	dialed, err := DialDuplex(session, "", addr.String())
	require.NoError(err)

	// write data in chunks with delays by sender
	payload := make([]byte, 10*4200)

	chunk_size := len(payload) / 16
	_, err = io.ReadFull(rand.Reader, payload)
	require.NoError(err)

	// a writer worker that sends a payload in chunks and then closes the stream
	errCh := make(chan error)
	go func() {
		defer wg.Done()
		defer dialed.Close()
		defer close(errCh)
		for i := int64(0); i < int64(len(payload)); {
			var msg []byte
			remains := payload[i:]
			if len(remains) < chunk_size {
				msg = remains
			} else {
				msg = remains[:chunk_size]
			}
			t.Logf("Writing %d of %d remaining bytes", len(msg), len(remains))
			n, err := io.Copy(dialed, bytes.NewBuffer(msg))
			if err != nil {
				errCh <- err
				return
			}
			if n != int64(chunk_size) {
				t.Logf("wrote %d less than expected", int64(len(msg))-n)
			}
			i += n
			// wait
			<-time.After(1 * time.Second)
		}
		// flush writebuf to network
		err := dialed.Sync()
		if err != nil {
			errCh <- err
		}
		t.Logf("Wrote all bytes to write buffer")

	}()

	// a reader worker that receives a payload

	result := make([]byte, len(payload))
	err2Ch := make(chan error)
	go func() {
		defer wg.Done()
		defer close(err2Ch)
		t.Logf("ReadFull begun")
		n, err := io.ReadFull(listener, result)
		if err != nil {
			t.Logf("ReadFull returned error after %d bytes: %v", n, err)
			err2Ch <- err
			return
		}
		t.Logf("Read %d bytes", n)
	}()

	// require that no errors occurred while reading or writing the data
	err, ok := <-errCh
	if !ok {
		require.NoError(err)
	}
	err, ok = <-err2Ch
	if !ok {
		require.NoError(err)
	}

	// wait until the routines have returned
	t.Logf("waiting for all routines to return")
	wg.Wait()
	t.Logf("all routines to returned")

	// stop the reader
	t.Logf("halting listener")
	t.Logf("Waiting for listener to Halt")
	listener.Halt()
	t.Logf("listener halted")

	// stop the sender
	t.Logf("Halting dialed")
	t.Logf("Waiting for dialed to Halt")
	dialed.Halt()
	t.Logf("dialed halted")
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
		m.Payload = make([]byte, 4200) //2 * FramePayloadSize)
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

		s.Sync()
		s.Halt()
		senderStreamState, err := s.Save()
		require.NoError(err)
		c, _ := mClient.NewClient(session)

		s, err = LoadStream(senderStreamState)
		require.NoError(err)

		// initialize a pigeonhole client with session
		trans := mClient.DuplexFromSeed(c, s.Initiator, []byte(s.LocalAddr().String()))
		// FIXME: Streams should support resetting sender/receivers on Geometry changes.
		if s.PayloadSize != PayloadSize(trans) {
			panic(ErrGeometryChanged)
		}

		// use pigeonhole transport
		s.SetTransport(trans)
		s.Start()
		r.Halt()
		receiverStreamState, err := r.Save()
		require.NoError(err)
		r, err = LoadStream(receiverStreamState)
		require.NoError(err)

		// set the transport
		r.SetTransport(trans)
		r.Start()
	}
	err = s.Close()
	require.NoError(err)
	err = r.Close()
	require.NoError(err)
	s.Halt()
	r.Halt()
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
	err = r.Close()
	require.NoError(err)
	r.Halt()
	s.Halt()
}

func init() {
	go func() {
		http.ListenAndServe("localhost:4242", nil)
	}()
	runtime.SetMutexProfileFraction(1)
	runtime.SetBlockProfileRate(1)
}

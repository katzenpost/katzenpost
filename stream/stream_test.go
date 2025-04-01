// stream_test.go - stream tests
// Copyright (C) 2024  Masala
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

package stream

import (
	"crypto/sha256"
	"encoding/base64"
	"github.com/katzenpost/hpqc/rand"
	"github.com/stretchr/testify/require"
	"io"
	"net/http"
	_ "net/http/pprof"
	"runtime"
	"testing"
	"time"
)

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

func TestStreamDial(t *testing.T) {
	require := require.New(t)
	trans := NewMockTransport()
	x := sha256.Sum256([]byte("TestStreamDial"))
	s, err := Dial(trans, "", base64.StdEncoding.EncodeToString(x[:]))
	require.NoError(err)
	_, err = s.Write([]byte("some friendly bytes"))
	require.NoError(err)
}

func TestStreamListen(t *testing.T) {
	require := require.New(t)
	trans := NewMockTransport()
	x := sha256.Sum256([]byte("TestStreamDial"))
	s, err := Listen(trans, "", base64.StdEncoding.EncodeToString(x[:]))
	require.NoError(err)
	_, err = s.Write([]byte("some friendly bytes"))
	require.NoError(err)
}

func TestSaveLoadStream(t *testing.T) {
	// initialize a listener stream
	require := require.New(t)
	trans := NewMockTransport()
	x := sha256.Sum256([]byte("TestStreamDial"))
	sl, err := Listen(trans, "", base64.StdEncoding.EncodeToString(x[:]))

	// initialize a dialer stream
	sd, err := Dial(trans, "", base64.StdEncoding.EncodeToString(x[:]))
	require.NoError(err)

	payload := make([]byte, 4200)
	_, err = io.ReadFull(rand.Reader, payload[:])
	require.NoError(err)

	// send some data
	t.Logf("Send payload")
	_, err = sd.Write(payload)
	require.NoError(err)
	t.Logf("Sent payload")
	t.Log(sl.String())

	// read partial data
	buf := make([]byte, 42)
	t.Logf("Reading 42 bytes of payload")
	n, err := sl.Read(buf)
	require.Equal(42, n)
	t.Logf("Read 42 bytes of payload")
	t.Log(sl.String())

	// stop the receiver
	<-time.After(4*time.Second + 20*time.Millisecond)
	t.Log("halting stream")
	sl.Halt()
	t.Log("halted stream")
	t.Log(sl.String())

	// save the stream
	t.Log("serialising stream")
	serialised, err := sl.Save()
	require.NoError(err)
	t.Log("serialised stream")
	t.Log(sl.String())

	// dump the stream variables
	t.Log(sl.String())

	// deserialize the stream
	sl, err = LoadStream(serialised)
	require.NoError(err)
	t.Log("deserialised stream")

	// dump the stream variables
	t.Log(sl.String())

	// start stream
	sl.StartWithTransport(trans)
	t.Log("(re)starting stream")
	t.Log(sl.String())

	// receive the rest of the data and verify it
	buf2 := make([]byte, 4200-42)
	t.Log("resuming read")
	n, err = io.ReadFull(sl, (buf2))
	require.NoError(err)
	require.Equal(len(buf2), n)
	require.Equal(append(buf, buf2...), payload)
	t.Log("resumed read")
	t.Log(sl.String())
}

func init() {
	go func() {
		http.ListenAndServe("localhost:8181", nil)
	}()
	runtime.SetMutexProfileFraction(1)
	runtime.SetBlockProfileRate(1)
}

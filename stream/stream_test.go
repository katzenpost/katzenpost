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
	//"github.com/katzenpost/hpqc/rand"
	"github.com/stretchr/testify/require"
	"io"
	"net/http"
	_ "net/http/pprof"
	"runtime"
	"testing"
	"time"
)

func TestSaveLoadStream(t *testing.T) {
	require := require.New(t)
	trans := NewMockTransport()
	sd, sl := newStreams(trans)

	payload := make([]byte, 4200)
	for i := 0; i < len(payload); i++ {
		payload[i] = uint8(i)
	}
	//_, err := io.ReadFull(rand.Reader, payload[:])
	//require.NoError(err)

	// send some data
	t.Logf("Send payload")
	_, err := sd.Write(payload)
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

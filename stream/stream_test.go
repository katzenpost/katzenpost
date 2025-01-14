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
	"github.com/stretchr/testify/require"
	"testing"
)

func TestFrameKey(t *testing.T) {
	t.Parallel()
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

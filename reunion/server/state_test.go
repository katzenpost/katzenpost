// state_test.go - Reunion server state tests.
// Copyright (C) 2020  David Stainton.
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

package server

import (
	"testing"

	"github.com/katzenpost/hpqc/rand"
	"github.com/katzenpost/katzenpost/reunion/commands"
	"github.com/stretchr/testify/require"
)

func TestStateSerialization1(t *testing.T) {
	t.Parallel()
	require := require.New(t)

	state1 := NewReunionState()
	t1 := commands.SendT1{
		Epoch:   123,
		Payload: []byte{0xDE, 0xAD, 0xBE, 0xEF},
	}
	err := state1.AppendMessage(&t1)
	require.NoError(err)
	b1, err := state1.Marshal()
	require.NoError(err)
	state2 := NewReunionState()
	err = state2.Unmarshal(b1)
	require.NoError(err)

	state1.t1Map.Range(func(t1hash, t1 interface{}) bool {
		t1hashAr, ok := t1hash.([32]byte)
		require.True(ok)
		t1bytes, ok := t1.([]byte)
		require.True(ok)
		myt1, ok := state2.t1Map.Load(t1hashAr)
		require.True(ok)
		require.Equal(t1bytes, myt1)
		return true
	})

	s, err := state1.Serializable()
	require.NoError(err)
	require.Equal(len(s.T1Map), 1)
	require.Equal(len(s.MessageMap), 1)

	r, err := state1.Marshal()
	require.NoError(err)

	state3 := new(SerializableReunionState)
	err = state3.Unmarshal(r)
	require.NoError(err)
	require.Equal(len(state3.T1Map), 1)
	require.Equal(len(state3.MessageMap), 1)

}

func TestStateSerialization2(t *testing.T) {
	t.Parallel()
	require := require.New(t)

	state1 := NewReunionState()
	t1 := commands.SendT2{
		SrcT1Hash: [32]byte{},
		DstT1Hash: [32]byte{},
		Payload:   []byte{0xDE, 0xAD, 0xBE, 0xEF},
	}
	_, err := rand.Reader.Read(t1.SrcT1Hash[:])
	require.NoError(err)
	_, err = rand.Reader.Read(t1.DstT1Hash[:])
	require.NoError(err)
	err = state1.AppendMessage(&t1)
	require.NoError(err)

	b1, err := state1.Marshal()
	require.NoError(err)
	state2 := NewReunionState()
	err = state2.Unmarshal(b1)
	require.NoError(err)

	state1.messageMap.Range(func(t1hash, messages interface{}) bool {
		t1hashAr, ok := t1hash.([32]byte)
		require.True(ok)

		messageList, ok := messages.(*LockedList)
		require.True(ok)
		item := messageList.list.Front()
		payload, ok := item.Value.(*T2Message)
		require.True(ok)

		state2.messageMap.Range(func(t1hash, messages interface{}) bool {
			t1hashAr2, ok := t1hash.([32]byte)
			require.True(ok)
			require.Equal(t1hashAr[:], t1hashAr2[:])

			messageList2, ok := messages.(*LockedList)
			require.True(ok)
			item2 := messageList2.list.Front()
			payload2, ok := item2.Value.(*T2Message)
			require.True(ok)

			require.Equal(payload.Payload, payload2.Payload)

			return true
		})

		return true
	})
}

func TestStateSerialization3(t *testing.T) {
	t.Parallel()
	require := require.New(t)

	state1 := NewReunionState()
	t1 := commands.SendT2{
		SrcT1Hash: [32]byte{},
		DstT1Hash: [32]byte{},
		Payload:   []byte{0xDE, 0xAD, 0xBE, 0xEF},
	}
	_, err := rand.Reader.Read(t1.SrcT1Hash[:])
	require.NoError(err)
	_, err = rand.Reader.Read(t1.DstT1Hash[:])
	require.NoError(err)
	err = state1.AppendMessage(&t1)
	require.NoError(err)
	b1, err := state1.Marshal()
	require.NoError(err)

	state2 := NewReunionState()
	err = state2.Unmarshal(b1)
	require.NoError(err)
	b2, err := state2.Marshal()
	require.NoError(err)
	require.Equal(b1, b2)
}

// commands.go - Reunion commands for the client and server.
// Copyright (C) 2019  David Stainton.
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

// Package commands provides commands used by the client and server.
package commands

import (
	"encoding/binary"

	"github.com/katzenpost/reunion/crypto"
)

type commandID byte

const (
	// ResponseStatusOK is an ErrorCode value used in responses from the Reunion DB
	// to indicate there was no error with the received query command.
	ResponseStatusOK = 0

	cmdOverhead = 1

	// Reunion client/DB commands.
	fetchState     commandID = 0
	stateResponse  commandID = 1
	sendT1         commandID = 2
	sendT2         commandID = 3
	sendT3         commandID = 4
	messageReponse commandID = 5
)

// Command interface represents query and response Reunion DB commands.
type Command interface {
	// ToBytes serializes the command and returns the resulting slice.
	ToBytes() []byte
}

// ReunionDatabase is an interface which represents the
// Reunion DB that protocol clients interact with.
type ReunionDatabase interface {
	// Query sends a query command to the Reunion DB and returns the
	// response command or an error.
	Query(command Command, haltCh chan interface{}) (Command, error)
}

// FetchState command is used by clients to fetch the current Reunion DB state.
type FetchState struct {
	// Epoch specifies the current Reunion epoch.
	Epoch uint64
	// ChunkIndex is the index indicating which chunk of the Reunion DB state
	// to fetch.
	ChunkIndex uint32
}

// ToBytes serializes the SendT1 command and returns the resulting slice.
func (s *FetchState) ToBytes() []byte {
	out := make([]byte, cmdOverhead+8+4)
	out[0] = byte(fetchState)
	binary.BigEndian.PutUint64(out[1:9], s.Epoch)
	binary.BigEndian.PutUint32(out[9:], s.ChunkIndex)
	return out
}

// StateResponse is sent to clients in response to a FetchState command.
type StateResponse struct {
	// ErrorCode indicates a specific error or status OK.
	ErrorCode uint8
	// Truncated indicates if the payload was truncated or not.
	Truncated bool
	// LeftOverChunksHint is the number of left over chunks if
	// the payload is truncated.
	LeftOverChunksHint uint32
	// Payload contains the Reunion DB state.
	Payload []byte
}

// ToBytes serializes the SendT1 command and returns the resulting slice.
func (s *StateResponse) ToBytes() []byte {
	out := make([]byte, cmdOverhead+1+1+4)
	out[0] = byte(stateResponse)
	truncated := uint8(0)
	if s.Truncated {
		truncated = uint8(1)
	}
	out[1] = truncated
	binary.BigEndian.PutUint32(out[2:6], s.LeftOverChunksHint)
	out = append(out, s.Payload...)
	return out
}

// SendT1 command is used by clients to send their T1 message to the Reunion DB.
type SendT1 struct {
	// Epoch specifies the current Reunion epoch.
	Epoch uint64

	// Payload contains the T1 message.
	Payload []byte
}

// ToBytes serializes the SendT1 command and returns the resulting slice.
func (s *SendT1) ToBytes() []byte {
	out := make([]byte, cmdOverhead+8)
	out[0] = byte(sendT1)
	binary.BigEndian.PutUint64(out[1:9], s.Epoch)
	out = append(out, s.Payload...)
	return out
}

// SendT2 command is used by clients to send their T2 message to the Reunion DB.
type SendT2 struct {
	// Epoch specifies the current Reunion epoch.
	Epoch uint64

	// T1Hash is the hash of the T1 message which this T2 message is replying.
	T1Hash [32]byte

	// Payload contains the T2 message.
	Payload []byte
}

// ToBytes serializes the SendT2 command and returns the resulting slice.
func (s *SendT2) ToBytes() []byte {
	out := make([]byte, cmdOverhead+8+32)
	out[0] = byte(sendT2)
	binary.BigEndian.PutUint64(out[1:9], s.Epoch)
	copy(out[9:], s.T1Hash[:])
	out = append(out, s.Payload...)
	return out
}

// SendT3 command is used by clients to send their T3 message to the Reunion DB.
type SendT3 struct {
	// Epoch specifies the current Reunion epoch.
	Epoch uint64

	// T2Hash is the hash of the T2 message which this T3 message is replying.
	T2Hash [32]byte

	// Payload contains the T3 message.
	Payload []byte
}

// ToBytes serializes the SendT2 command and returns the resulting slice.
func (s *SendT3) ToBytes() []byte {
	out := make([]byte, cmdOverhead+8+32)
	out[0] = byte(sendT3)
	binary.BigEndian.PutUint64(out[1:9], s.Epoch)
	copy(out[9:], s.T2Hash[:])
	out = append(out, s.Payload...)
	return out
}

// MessageResponse command is used by the server to send clients the
// status of the previously received send command (SendT1, SendT2 and, SendT3).
type MessageResponse struct {
	// ErrorCode indicates a specific error or status OK.
	ErrorCode uint8
}

// ToBytes serializes the MessageResponse command and returns the resulting slice.
func (s *MessageResponse) ToBytes() []byte {
	out := make([]byte, cmdOverhead+1)
	out[0] = byte(messageReponse)
	out[1] = s.ErrorCode
	return out
}

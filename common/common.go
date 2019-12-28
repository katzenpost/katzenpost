// common.go - Reunion common types for both client and server.
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

// Package common provides common types used by both the client and server.
package common

import ()

// Command interface represents query and response Reunion DB commands.
type Command interface {
	// ToBytes appends the serialized command to slice b, and returns the
	// resulting slice.
	ToBytes(b []byte) []byte
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

// SendT1 command is used by clients to send their T1 message to the Reunion DB.
type SendT1 struct {
	// Epoch specifies the current Reunion epoch.
	Epoch uint64

	// Payload contains the T1 message.
	Payload []byte
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

// SendT3 command is used by clients to send their T3 message to the Reunion DB.
type SendT3 struct {
	// Epoch specifies the current Reunion epoch.
	Epoch uint64

	// T2Hash is the hash of the T2 message which this T3 message is replying.
	T2Hash [32]byte

	// Payload contains the T3 message.
	Payload []byte
}

// SentMessageResponse command is used by the server to send clients the
// status of the previously received send command (SendT1, SendT2 and, SendT3).
type SentMessageResponse struct {
	// ErrorCode indicates a specific error or status OK.
	ErrorCode uint8
}

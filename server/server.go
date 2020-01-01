// server.go - Reunion server.
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

// Package server provides the Reunion protocol server.
package server

import (
	"github.com/katzenpost/reunion/commands"
)

// ReunionStateChunk is a chunk of the state of the Reunion DB.
// This is the type which is fetched by the FetchState
// command.
type ReunionStateChunk struct {
	// Sequence is incremented with every change to the DB.
	Sequence uint64
	// T1s is a slice of the SendT1 command received from a client.
	T1s []*commands.SendT1
	// T2s is a slice of the SendT2 command received from a client.
	T2s []*commands.SendT2
	// T3s is a slice of the SendT3 command received from a client.
	T3s []*commands.SendT3
}

// NewReunionStateChunk creates a new ReunionStateChunk.
func NewReunionStateChunk() *ReunionStateChunk {
	return &ReunionStateChunk{
		Sequence: 0,
		T1s:      make([]*commands.SendT1, 0),
		T2s:      make([]*commands.SendT2, 0),
		T3s:      make([]*commands.SendT3, 0),
	}
}

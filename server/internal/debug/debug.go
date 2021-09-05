// debug.go - Katzenpost server debug bits and peices.
// Copyright (C) 2017  Yawning Angel.
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

// Package debug implements useful helper routines to aid debugging.
package debug

import (
	"encoding/base64"
	"github.com/katzenpost/core/sphinx/constants"
)

// NodeIDToPrintString pretty-prints a node identifier.
func NodeIDToPrintString(id *[constants.NodeIDLength]byte) string {
	return base64.StdEncoding.EncodeToString(id[:])
}

// BytesToPrintString pretty-prints a byte slice.
func BytesToPrintString(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

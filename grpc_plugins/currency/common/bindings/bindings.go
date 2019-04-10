// bindings.go - Katzenpost currency common library C binding
// Copyright (C) 2018  David Stainton.
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

// Package main for client C binding.
package main

import "C"

import (
	"github.com/katzenpost/server_plugins/grpc_plugins/currency/common"
)

const (
	// currency tickers are three characters in length
	tickerLen = 3
)

//export NewRequest
func NewRequest(ticker, txHex *C.char) *C.char {
	myTicker := C.GoString(ticker)
	myTx := C.GoString(txHex)
	request := common.NewRequest(myTicker, myTx)
	myJson := request.ToJson()
	return C.CString(string(myJson))
}

func main() {}

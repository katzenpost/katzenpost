// main.go - memspool service using cbor plugin system
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

package main

import (
	"fmt"
	"net"
	"net/http"
	"os"

	"github.com/katzenpost/server/cborplugin"
	"github.com/ugorji/go/codec"
)

var cborHandle = new(codec.CborHandle)

func parametersHandler(response http.ResponseWriter, req *http.Request) {
	params := new(cborplugin.Parameters)
	var serialized []byte
	enc := codec.NewEncoderBytes(&serialized, new(codec.CborHandle))
	if err := enc.Encode(params); err != nil {
		panic(err)
	}
	_, err := response.Write(serialized)
	if err != nil {
		panic(err)
	}
}

func requestHandler(spoolMap *MemSpoolMap, response http.ResponseWriter, request *http.Request) {
	req := cborplugin.Request{
		Payload: make([]byte, 0),
	}
	err := codec.NewDecoder(request.Body, cborHandle).Decode(&req)
	if err != nil {
		panic(err)
	}
	spoolRequest := SpoolRequest{}
	err = codec.NewDecoderBytes(req.Payload, cborHandle).Decode(&spoolRequest)
	if err != nil {
		panic(err)
	}
	spoolResponse := handleSpoolRequest(spoolMap, &spoolRequest)
	var spoolResponseSerialized []byte
	enc := codec.NewEncoderBytes(&spoolResponseSerialized, cborHandle)
	if err := enc.Encode(spoolResponse); err != nil {
		panic(err)
	}
	reply := cborplugin.Response{
		Payload: spoolResponseSerialized,
	}
	var serialized []byte
	enc = codec.NewEncoderBytes(&serialized, cborHandle)
	if err := enc.Encode(reply); err != nil {
		panic(err)
	}
	_, err = response.Write(serialized)
	if err != nil {
		panic(err)
	}
}

func main() {
	server := http.Server{}
	socketFile := fmt.Sprintf("/tmp/%d.echo.socket", os.Getpid())

	unixListener, err := net.Listen("unix", socketFile)
	if err != nil {
		panic(err)
	}
	spoolMap := NewMemSpoolMap()
	_requestHandler := func(response http.ResponseWriter, request *http.Request) {
		requestHandler(spoolMap, response, request)
	}
	http.HandleFunc("/request", _requestHandler)
	http.HandleFunc("/parameters", parametersHandler)
	fmt.Printf("%s\n", socketFile)
	server.Serve(unixListener)
	os.Remove(socketFile)
}

// main.go - echo service using cbor plugin system
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

package main

import (
	"fmt"
	"net"
	"net/http"
	"os"

	"github.com/katzenpost/server/cborplugin"
	"github.com/ugorji/go/codec"
)

func parametersHandler(response http.ResponseWriter, req *http.Request) {
	params := cborplugin.Parameters{
		Map: make(map[string]string),
	}
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

func requestHandler(response http.ResponseWriter, req *http.Request) {
	resp := cborplugin.Request{
		Payload: make([]byte, 0),
	}
	err := codec.NewDecoder(req.Body, new(codec.CborHandle)).Decode(&resp)
	if err != nil {
		panic(err)
	}
	reply := cborplugin.Response{
		Payload: resp.Payload,
	}
	var serialized []byte
	enc := codec.NewEncoderBytes(&serialized, new(codec.CborHandle))
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
	http.HandleFunc("/request", requestHandler)
	http.HandleFunc("/parameters", parametersHandler)
	fmt.Printf("%s\n", socketFile)
	server.Serve(unixListener)
	os.Remove(socketFile)
}

package main

import (
	"fmt"
	"net"
	"net/http"
	"os"

	"github.com/katzenpost/server/cborplugin"
	"github.com/ugorji/go/codec"
)

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
	fmt.Printf("%s\n", socketFile)
	server.Serve(unixListener)
	os.Remove(socketFile)
}

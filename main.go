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
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path"

	"github.com/katzenpost/client/multispool"
	"github.com/katzenpost/server/cborplugin"
	"github.com/op/go-logging"
	"github.com/ugorji/go/codec"
)

var cborHandle = new(codec.CborHandle)
var log = logging.MustGetLogger("memspool")
var logFormat = logging.MustStringFormatter(
	"%{level:.4s} %{id:03x} %{message}",
)

func stringToLogLevel(level string) (logging.Level, error) {
	switch level {
	case "DEBUG":
		return logging.DEBUG, nil
	case "INFO":
		return logging.INFO, nil
	case "NOTICE":
		return logging.NOTICE, nil
	case "WARNING":
		return logging.WARNING, nil
	case "ERROR":
		return logging.ERROR, nil
	case "CRITICAL":
		return logging.CRITICAL, nil
	}
	return -1, fmt.Errorf("invalid logging level %s", level)
}

func setupLoggerBackend(level logging.Level, writer io.Writer) logging.LeveledBackend {
	format := logFormat
	backend := logging.NewLogBackend(writer, "", 0)
	formatter := logging.NewBackendFormatter(backend, format)
	leveler := logging.AddModuleLevel(formatter)
	leveler.SetLevel(level, "memspool")
	return leveler
}

func parametersHandler(response http.ResponseWriter, req *http.Request) {
	log.Debug("parametersHandler")

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
	log.Debug("requestHandler")

	req := cborplugin.Request{
		Payload: make([]byte, 0),
	}
	err := codec.NewDecoder(request.Body, cborHandle).Decode(&req)
	if err != nil {
		log.Debugf("failed to decode Request: %s", err)
		panic(err)
	}
	spoolRequest := multispool.SpoolRequest{}
	spoolRequestLen := binary.BigEndian.Uint32(req.Payload[:4])
	log.Debugf("before decoding SpoolRequest len %d", len(req.Payload))
	err = codec.NewDecoderBytes(req.Payload[4:spoolRequestLen+4], cborHandle).Decode(&spoolRequest)
	if err != nil {
		log.Debugf("failed to decode SpoolRequest: %s", err)
		panic(err)
	}
	log.Debug("before calling handleSpoolRequest")
	spoolResponse := handleSpoolRequest(spoolMap, &spoolRequest)
	log.Debug("after calling handleSpoolRequest")

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
	log.Debug("success")
}

func main() {
	var logLevel string
	var logDir string
	flag.StringVar(&logDir, "log_dir", "", "logging directory")
	flag.StringVar(&logLevel, "log_level", "DEBUG", "logging level could be set to: DEBUG, INFO, NOTICE, WARNING, ERROR, CRITICAL")
	flag.Parse()

	level, err := stringToLogLevel(logLevel)
	if err != nil {
		fmt.Println("Invalid logging-level specified.")
		os.Exit(1)
	}

	// Ensure that the log directory exists.
	s, err := os.Stat(logDir)
	if os.IsNotExist(err) {
		fmt.Printf("Log directory '%s' doesn't exist.", logDir)
		os.Exit(1)
	}
	if !s.IsDir() {
		fmt.Println("Log directory must actually be a directory.")
		os.Exit(1)
	}

	// Log to a file.
	logFile := path.Join(logDir, fmt.Sprintf("memspool.%d.log", os.Getpid()))
	f, err := os.Create(logFile)
	logBackend := setupLoggerBackend(level, f)
	log.SetBackend(logBackend)

	server := http.Server{}
	socketFile := fmt.Sprintf("/tmp/%d.memspool.socket", os.Getpid())

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
	log.Debug("memspool server started.")

	server.Serve(unixListener)
	os.Remove(socketFile)
}

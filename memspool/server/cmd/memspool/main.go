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
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"path"
	"path/filepath"

	"github.com/fxamacker/cbor/v2"
	"github.com/katzenpost/katzenpost/memspool/common"
	"github.com/katzenpost/katzenpost/memspool/server"
	"github.com/katzenpost/katzenpost/server/cborplugin"
	"gopkg.in/op/go-logging.v1"
)

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
	serialized, err := cbor.Marshal(params)
	if err != nil {
		panic(err)
	}
	n, err := response.Write(serialized)
	if err != nil || n != len(serialized) {
		panic(err)
	}
}

func requestHandler(spoolMap *server.MemSpoolMap, response http.ResponseWriter, request *http.Request) {
	log.Debug("requestHandler")

	req := cborplugin.Request{
		Payload: make([]byte, 0),
	}
	buf, err := ioutil.ReadAll(request.Body)
	defer request.Body.Close()
	if err != nil {
		http.Error(response, err.Error(), 500)
		return
	}
	err = cbor.Unmarshal(buf, &req)
	if err != nil {
		log.Debugf("failed to decode Request: %s", err)
		http.Error(response, err.Error(), 500)
		return
	}
	spoolRequest := common.SpoolRequest{}
	spoolRequestLen := binary.BigEndian.Uint32(req.Payload[:4])
	log.Debugf("before decoding SpoolRequest len %d", len(req.Payload))
	err = cbor.Unmarshal(req.Payload[4:spoolRequestLen+4], &spoolRequest)
	if err != nil {
		log.Debugf("failed to decode SpoolRequest: %s", err)
		http.Error(response, err.Error(), 500)
		return
	}
	log.Debug("before calling handleSpoolRequest")
	spoolResponse := server.HandleSpoolRequest(spoolMap, &spoolRequest, log)
	log.Debug("after calling handleSpoolRequest")

	spoolResponseSerialized, err := spoolResponse.Encode()
	if err != nil {
		log.Debugf("failed to encode SpoolResponse: %s", err)
		http.Error(response, err.Error(), 500)
		return
	}
	reply := cborplugin.Response{
		Payload: spoolResponseSerialized,
	}
	serialized, err := cbor.Marshal(reply)
	if err != nil {
		log.Debugf("failed to encode cborplugin.Response: %s", err)
		http.Error(response, err.Error(), 500)
		return
	}
	_, err = response.Write(serialized)
	if err != nil {
		log.Debugf("failed to write response: %s", err)
		return
	}
	log.Debug("success")
}

func main() {
	var logLevel string
	var logDir string
	var dataStore string
	flag.StringVar(&dataStore, "data_store", "", "data storage file path")
	flag.StringVar(&logDir, "log_dir", "", "logging directory")
	flag.StringVar(&logLevel, "log_level", "DEBUG", "logging level could be set to: DEBUG, INFO, NOTICE, WARNING, ERROR, CRITICAL")
	flag.Parse()

	if dataStore == "" {
		fmt.Println("Must specify a data storage file path.")
		os.Exit(1)
	}

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
	if err != nil {
		fmt.Println("Invalid logfile specified.")
		os.Exit(1)
	}

	logBackend := setupLoggerBackend(level, f)
	log.SetBackend(logBackend)

	httpServer := http.Server{}
	tmpDir, err := ioutil.TempDir("", "memspool_server")
	if err != nil {
		panic(err)
	}
	socketFile := filepath.Join(tmpDir, fmt.Sprintf("%d.memspool.socket", os.Getpid()))

	unixListener, err := net.Listen("unix", socketFile)
	if err != nil {
		panic(err)
	}
	spoolMap, err := server.NewMemSpoolMap(dataStore, log)
	if err != nil {
		panic(err)
	}

	_requestHandler := func(response http.ResponseWriter, request *http.Request) {
		requestHandler(spoolMap, response, request)
	}
	http.HandleFunc("/request", _requestHandler)
	http.HandleFunc("/parameters", parametersHandler)

	fmt.Printf("%s\n", socketFile)
	log.Debug("memspool server started.")

	httpServer.Serve(unixListener)
	os.Remove(socketFile)
	spoolMap.Shutdown()
}

// main.go - panda service using cbor plugin system
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
	"errors"
	"flag"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"time"

	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/panda/server"
	"github.com/katzenpost/katzenpost/server/cborplugin"
	"gopkg.in/op/go-logging.v1"
)

func main() {
	var logLevel string
	var logDir string
	var dwellTime string
	var writeBackInterval string
	var fileStore string

	flag.StringVar(&logDir, "log_dir", "", "logging directory")
	flag.StringVar(&logLevel, "log_level", "DEBUG", "logging level could be set to: DEBUG, INFO, NOTICE, WARNING, ERROR, CRITICAL")
	flag.StringVar(&dwellTime, "dwell_time", "336h", "ciphertext max dwell time before garbage collection")
	flag.StringVar(&writeBackInterval, "writeBackInterval", "1h", "GC and write-back cache interval")
	flag.StringVar(&fileStore, "fileStore", "", "The file path of our on disk storage.")

	flag.Parse()

	dwellDuration, err := time.ParseDuration(dwellTime)
	if err != nil {
		panic(err)
	}
	writeBackDuration, err := time.ParseDuration(writeBackInterval)
	if err != nil {
		panic(err)
	}
	if fileStore == "" {
		panic("Invalid fileStore specified.")
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
	logFile := path.Join(logDir, fmt.Sprintf("panda.%d.log", os.Getpid()))
	logBackend, err := log.New(logFile, logLevel, false)
	if err != nil {
		panic(err)
	}
	serverLog := logBackend.GetLogger("panda_server")
	serverLog.Info("panda server started")

	// start service
	tmpDir, err := os.MkdirTemp("", "panda_server")
	if err != nil {
		panic(err)
	}
	socketFile := filepath.Join(tmpDir, fmt.Sprintf("%d.panda.socket", os.Getpid()))

	panda, err := server.New(serverLog, fileStore, dwellDuration, writeBackDuration)
	if err != nil {
		panic(err)
	}

	var server *cborplugin.Server
	h := &pandaRequestHandler{p: panda, log: serverLog}
	server = cborplugin.NewServer(serverLog, socketFile, h)
	// emit socketFile to stdout, because this tells the mix server where to connect
	fmt.Printf("%s\n", socketFile)
	server.Accept()
	server.Wait()
	os.Remove(socketFile)
}

type pandaRequestHandler struct {
	p   *server.Panda
	log *logging.Logger
}

// OnCommand processes a SpoolRequest and returns a SpoolResponse
func (s *pandaRequestHandler) OnCommand(cmd cborplugin.Command) (cborplugin.Command, error) {
	switch r := cmd.(type) {
	case *cborplugin.Request:
		// the padding bytes were not stripped because
		// without parsing the start of Payload we wont
		// know how long it is, so we will use a streaming
		// decoder and simply return the first cbor object
		// and then discard the decoder and buffer
		pandaResponse, err := s.p.OnRequest(r.ID, r.Payload, r.HasSURB)
		if err != nil {
			s.log.Errorf("OnCommand called with invalid request")
			return nil, err
		}
		return &cborplugin.Response{Payload: pandaResponse}, nil
	case *cborplugin.ParametersRequest:
		// panda doesn't set any custom parameters in the PKI, so let the
		// cborplugin.Client populate cborplugin.Parameters{}.
		// and we don't know what the required endpoint field should be anyway
		return nil, nil
	default:
		s.log.Errorf("OnCommand called with unknown Command type")
		return nil, errors.New("Invalid Command type")
	}
}

func (s *pandaRequestHandler) RegisterConsumer(svr *cborplugin.Server) {
}

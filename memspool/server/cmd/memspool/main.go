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
	"bytes"
	"errors"
	"flag"
	"fmt"
	"github.com/fxamacker/cbor/v2"
	"gopkg.in/op/go-logging.v1"
	"os"
	"path"
	"path/filepath"

	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/memspool/common"
	"github.com/katzenpost/katzenpost/memspool/server"
	"github.com/katzenpost/katzenpost/server/cborplugin"
)

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
	logFile := path.Join(logDir, fmt.Sprintf("memspool.log"))
	logBackend, err := log.New(logFile, logLevel, false)
	if err != nil {
		panic(err)
	}
	serverLog := logBackend.GetLogger("memspool_server")

	// start service
	tmpDir, err := os.MkdirTemp("", "memspool_server")
	if err != nil {
		panic(err)
	}
	socketFile := filepath.Join(tmpDir, fmt.Sprintf("%d.memspool.socket", os.Getpid()))

	spoolMap, err := server.NewMemSpoolMap(dataStore, serverLog)
	if err != nil {
		panic(err)
	}

	var server *cborplugin.Server
	h := &spoolRequestHandler{m: spoolMap, log: serverLog}
	server = cborplugin.NewServer(serverLog, socketFile, new(cborplugin.RequestFactory), h)
	// emit socketFile to stdout, because this tells the mix server where to connect
	fmt.Printf("%s\n", socketFile)
	server.Accept()
	server.Wait()
	spoolMap.Shutdown()
	os.Remove(socketFile)
}

type spoolRequestHandler struct {
	m   *server.MemSpoolMap
	log *logging.Logger
	write func(cborplugin.Command)
}

// OnCommand processes a SpoolRequest and returns a SpoolResponse
func (s *spoolRequestHandler) OnCommand(cmd cborplugin.Command) error {
	switch r := cmd.(type) {
	case *cborplugin.Request:
		// the padding bytes were not stripped because
		// without parsing the start of Payload we wont
		// know how long it is, so we will use a streaming
		// decoder and simply return the first cbor object
		// and then discard the decoder and buffer
		req := &common.SpoolRequest{}
		dec := cbor.NewDecoder(bytes.NewReader(r.Payload))
		err := dec.Decode(req)
		if err != nil {
			return err
		}
		if s.write == nil {
			return errors.New("Plugin not registered")
		}

		go func() {
			resp := server.HandleSpoolRequest(s.m, req, s.log)
			rawResp, err := resp.Marshal()
			if err != nil {
				return
			}
			s.write(&cborplugin.Response{ID: r.ID, SURB: r.SURB, Payload: rawResp})
		}()
		return nil
	default:
		s.log.Errorf("OnCommand called with unknown Command type")
		return errors.New("Invalid Command type")
	}
}

func (s *spoolRequestHandler) RegisterConsumer(svr *cborplugin.Server) {
	// save the handle to the cborplugin Write method, in order to send responses async
	s.write = svr.Write
}

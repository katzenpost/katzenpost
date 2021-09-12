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
	"errors"
	"flag"
	"fmt"
	"golang.org/x/sync/errgroup"
	"gopkg.in/op/go-logging.v1"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"

	//"github.com/fxamacker/cbor/v2"
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
	logFile := path.Join(logDir, fmt.Sprintf("memspool.%d.log", os.Getpid()))
	logBackend, err := log.New(logFile, logLevel, false)
	if err != nil {
		panic(err)
	}
	serverLog := logBackend.GetLogger("memspool_server")

	// start service
	tmpDir, err := ioutil.TempDir("", "memspool_server")
	if err != nil {
		panic(err)
	}
	socketFile := filepath.Join(tmpDir, fmt.Sprintf("%d.memspool.socket", os.Getpid()))

	// requestFactory turns CommandIO payloads into SpoolRequests
	spoolRequests := new(spoolRequestFactory)
	spoolMap, err := server.NewMemSpoolMap(dataStore, serverLog)
	if err != nil {
		panic(err)
	}

	var server *cborplugin.Server
	g := new(errgroup.Group)
	g.Go(func() error {
		h := &spoolRequestHandler{m: spoolMap, log: serverLog}
		server = cborplugin.NewServer(serverLog, socketFile, spoolRequests, h)
		return nil
	})
	err = g.Wait()
	fmt.Printf("%s\n", socketFile)
	server.Accept()
	server.Wait()
	spoolMap.Shutdown()
	os.Remove(socketFile)

	if err != nil {
		panic(err)
	}
}

// this daemon expects cbor-encoded SpoolRequests via its socket
type spoolRequestFactory struct {
}

func (s *spoolRequestFactory) Build() cborplugin.Command {
	return new(common.SpoolRequest)
}

type spoolRequestHandler struct {
	m   *server.MemSpoolMap
	log *logging.Logger
}

// OnCommand processes a SpoolRequest and returns a SpoolResponse
func (s *spoolRequestHandler) OnCommand(cmd cborplugin.Command) (cborplugin.Command, error) {
	switch r := cmd.(type) {
	case *common.SpoolRequest:
		return server.HandleSpoolRequest(s.m, r, s.log), nil
	default:
		return nil, errors.New("Invalid Command type")
	}
}

func (s *spoolRequestHandler) RegisterConsumer(svr *cborplugin.Server) {
}

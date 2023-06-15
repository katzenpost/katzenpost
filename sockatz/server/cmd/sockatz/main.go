// main.go - sockatz katzenpost service daemon
// Copyright (C) 2023  Masala
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
	"flag"
	"fmt"
	"io/ioutil"
	"net/http"
	_ "net/http/pprof"
	"os"
	"path"
	"path/filepath"
	"runtime"

	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/server/cborplugin"
	"github.com/katzenpost/katzenpost/sockatz/server"
)

func main() {
	var logLevel string
	var maxRequests int
	var logDir string
	var clientCfg string
	flag.StringVar(&clientCfg, "cfg", "", "client configuration")
	flag.StringVar(&logDir, "log_dir", "", "logging directory")
	flag.IntVar(&maxRequests, "max_requests", 420, "number of concurrent workers")
	flag.StringVar(&logLevel, "log_level", "DEBUG", "logging level could be set to: DEBUG, INFO, NOTICE, WARNING, ERROR, CRITICAL")
	flag.Parse()

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
	logFile := path.Join(logDir, fmt.Sprintf("sockatz.%d.log", os.Getpid()))
	logBackend, err := log.New(logFile, logLevel, false)
	if err != nil {
		panic(err)
	}
	serverLog := logBackend.GetLogger("sockatz_server")

	// start service
	tmpDir, err := ioutil.TempDir("", "sockatz_server")
	if err != nil {
		panic(err)
	}
	socketFile := filepath.Join(tmpDir, fmt.Sprintf("%d.sockatz.socket", os.Getpid()))

	// get a client connection to the mixnet
	s, err = os.Stat(clientCfg)
	if os.IsNotExist(err) {
		panic(err)
		fmt.Printf("Client config '%s' doesn't exist.", clientCfg)
		os.Exit(1)
	}

	// XXX: consider the possible/typical configuration:
	// a provider node that is not an entry node to the network
	// may choose to allow local connections, or add a user account for this worker
	// TODO: extend cbor worker interface to provide a client configuration
	sockatzServer, err := server.NewSockatz(clientCfg, logBackend)
	if err != nil {
		panic(err)
	}
	cmdBuilder := new(cborplugin.RequestFactory)
	server := cborplugin.NewServer(serverLog, socketFile, cmdBuilder, sockatzServer)
	// XXX: MUST PRINT THIS LINE FOR KATZENPOST SERVER TO CONNECT !!!
	fmt.Printf("%s\n", socketFile)
	server.Accept()
	server.Wait()
	sockatzServer.Halt()
	os.Remove(socketFile)
}

func init() {
	go func() {
		http.ListenAndServe("localhost:8282", nil)
	}()
	runtime.SetMutexProfileFraction(1)
	runtime.SetBlockProfileRate(1)
}

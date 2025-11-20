// main.go - scratch katzenpost service daemon
// Copyright (C) 2021  Masala
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
	"os"
	"path"
	"path/filepath"

	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/scratch/server"
	"github.com/katzenpost/katzenpost/server/cborplugin"
)

const (
	defaultScratchSize = 0x1 << 32 // 4B entries
	defaultGCSize         = 0x1 << 30 // 1B entries
)

func main() {
	var logLevel string
	var logDir string
	var dbFile string
	var scratchSize int
	var gcSize int
	flag.StringVar(&dbFile, "db", "", "database file")
	flag.StringVar(&logDir, "log_dir", "", "logging directory")
	flag.StringVar(&logLevel, "log_level", "DEBUG", "logging level could be set to: DEBUG, INFO, NOTICE, WARNING, ERROR, CRITICAL")
	flag.IntVar(&scratchSize, "size", defaultScratchSize, "number of entries to retain")
	flag.IntVar(&gcSize, "gc", defaultGCSize, "number of entries to batch garbage collect")
	flag.Parse()

	// Verify that a storage path is provided.
	if dbFile == "" {
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
	logFile := path.Join(logDir, fmt.Sprintf("scratch.%d.log", os.Getpid()))
	logBackend, err := log.New(logFile, logLevel, false)
	if err != nil {
		panic(err)
	}
	serverLog := logBackend.GetLogger("scratch_server")

	// start service
	tmpDir, err := ioutil.TempDir("", "scratch_server")
	if err != nil {
		panic(err)
	}
	socketFile := filepath.Join(tmpDir, fmt.Sprintf("%d.scratch.socket", os.Getpid()))

	scratchServer, err := server.NewScratch(dbFile, serverLog, gcSize, scratchSize)
	if err != nil {
		panic(err)
	}
	cmdBuilder := new(cborplugin.RequestFactory)
	server := cborplugin.NewServer(serverLog, socketFile, cmdBuilder, scratchServer)
	fmt.Printf("%s\n", socketFile) // are you for fucking real right now
	server.Accept()
	server.Wait()
	scratchServer.Shutdown()
	os.Remove(socketFile)
}

// main.go - Reunion server using the Katzenpost mix server cbor plugin system.
// Copyright (C) 2020  David Stainton.
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
	"golang.org/x/sync/errgroup"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"

	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/reunion/epochtime/katzenpost"
	"github.com/katzenpost/katzenpost/reunion/server"
	"github.com/katzenpost/katzenpost/server/cborplugin"
)

func parametersHandler(clock *katzenpost.Clock) cborplugin.Parameters {
	params := make(cborplugin.Parameters)
	epoch, _, _ := clock.Now()
	params["epoch"] = fmt.Sprintf("[%d, %d, %d]", epoch-1, epoch, epoch+1)
	return params
}

func main() {
	logDir := flag.String("log_dir", "", "logging directory")
	logPath := flag.String("log", "", "Log file path. Default STDOUT.")
	logLevel := flag.String("log_level", "DEBUG", "logging level could be set to: DEBUG, INFO, NOTICE, WARNING, ERROR, CRITICAL")
	stateFilePath := flag.String("s", "statefile", "State file path.")
	epochClockName := flag.String("epochClock", "katzenpost", "The epoch-clock to use.")
	flag.Parse()

	if *epochClockName != "katzenpost" {
		panic("Thus far only the Katzenpost epoch clock is supported in this server implementation.")
	}

	// Ensure that the log directory exists.
	s, err := os.Stat(*logDir)
	if os.IsNotExist(err) {
		fmt.Printf("Log directory '%s' doesn't exist.", *logDir)
		os.Exit(1)
	}
	if !s.IsDir() {
		fmt.Println("Log directory must actually be a directory.")
		os.Exit(1)
	}

	// Log to a file
	logFile := path.Join(*logDir, fmt.Sprintf("panda.%d.log", os.Getpid()))
	logBackend, err := log.New(logFile, *logLevel, false)
	if err != nil {
		panic(err)
	}
	serverLog := logBackend.GetLogger("reunion_server")
	serverLog.Info("reunion server started")

	// start service
	tmpDir, err := ioutil.TempDir("", "reunion_server")
	if err != nil {
		panic(err)
	}
	socketFile := filepath.Join(tmpDir, fmt.Sprintf("%d.reunion.socket", os.Getpid()))
	reunionServer, err := server.NewServer(new(katzenpost.Clock), *stateFilePath, *logPath, *logLevel)

	if err != nil {
		panic(err)
	}

	var server *cborplugin.Server
	g := new(errgroup.Group)
	g.Go(func() error {
		server = cborplugin.NewServer(serverLog, socketFile, new(cborplugin.RequestFactory), reunionServer)
		return nil
	})
	err = g.Wait()
	fmt.Printf("%s\n", socketFile)
	server.Accept()
	server.Wait()
	os.Remove(socketFile)

	if err != nil {
		panic(err)
	}
}

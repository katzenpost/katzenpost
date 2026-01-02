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
	"errors"
	"flag"
	"fmt"
	"os"
	"path"
	"path/filepath"

	"github.com/carlmjohnson/versioninfo"

	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/server/cborplugin"
)

type Echo struct {
	write func(cborplugin.Command)
}

func (e *Echo) OnCommand(cmd cborplugin.Command) error {
	switch r := cmd.(type) {
	case *cborplugin.Request:
		go func() {
			e.write(&cborplugin.Response{ID: r.ID, SURB: r.SURB, Payload: r.Payload})
		}()
		return nil
	default:
		return errors.New("echo-plugin: Invalid Command type")
	}
}

func (e *Echo) RegisterConsumer(s *cborplugin.Server) {
	e.write = s.Write
}

// GetParameters satisfies the cborplugin.ServerPlugin interface.
// This plugin does not need to advertise any dynamic parameters in the PKI,
// so it returns nil.
func (e *Echo) GetParameters() cborplugin.Parameters {
	return nil
}

func main() {
	var logLevel string
	var logDir string
	flag.StringVar(&logDir, "log_dir", "", "logging directory")
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
	logFile := path.Join(logDir, fmt.Sprintf("echo.%d.log", os.Getpid()))
	logBackend, err := log.New(logFile, logLevel, false)
	if err != nil {
		panic(err)
	}
	serverLog := logBackend.GetLogger("echo_server")
	serverLog.Noticef("Katzenpost echo-plugin version: %s", versioninfo.Short())
	serverLog.Notice("Katzenpost is still pre-alpha.  DO NOT DEPEND ON IT FOR STRONG SECURITY OR ANONYMITY.")

	// start service
	tmpDir, err := os.MkdirTemp("", "echo_server")
	if err != nil {
		panic(err)
	}
	socketFile := filepath.Join(tmpDir, fmt.Sprintf("%d.echo.socket", os.Getpid()))
	echo := new(Echo)

	var server *cborplugin.Server
	server = cborplugin.NewServer(serverLog, socketFile, new(cborplugin.RequestMessageFactory), echo)
	fmt.Printf("%s\n", socketFile)
	server.Accept()
	server.Wait()
	err = os.Remove(socketFile)
	if err != nil {
		panic(err)
	}
}

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
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	kpcommon "github.com/katzenpost/katzenpost/common"
	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/server/cborplugin"
)

type echoConfig struct {
	logDir   string
	logLevel string
}

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

func main() {
	cmd := newRootCommand()
	cmd.SetArgs(normalizeLegacyArgs(os.Args[1:]))
	kpcommon.ExecuteWithFang(cmd)
}

func normalizeLegacyArgs(args []string) []string {
	normalized := append([]string(nil), args...)
	for i, arg := range normalized {
		switch strings.SplitN(arg, "=", 2)[0] {
		case "-log_dir", "-log_level":
			normalized[i] = "-" + arg
		}
	}
	return normalized
}

func newRootCommand() *cobra.Command {
	var cfg echoConfig
	cmd := &cobra.Command{
		Use:   "echo-plugin",
		Short: "Katzenpost echo service plugin",
		Run: func(cmd *cobra.Command, args []string) {
			runEcho(cfg)
		},
	}
	cmd.Flags().StringVar(&cfg.logDir, "log_dir", "", "logging directory")
	cmd.Flags().StringVar(&cfg.logLevel, "log_level", "DEBUG", "logging level could be set to: DEBUG, INFO, NOTICE, WARNING, ERROR, CRITICAL")
	return cmd
}

func runEcho(cfg echoConfig) {
	// Ensure that the log directory exists.
	s, err := os.Stat(cfg.logDir)
	if os.IsNotExist(err) {
		cborplugin.FailStartup("echo-plugin", fmt.Errorf("log directory %q doesn't exist", cfg.logDir))
	}
	if !s.IsDir() {
		cborplugin.FailStartup("echo-plugin", fmt.Errorf("log directory %q is not a directory", cfg.logDir))
	}

	// Log to a file.
	logFile := path.Join(cfg.logDir, fmt.Sprintf("echo.%d.log", os.Getpid()))
	logBackend, err := log.New(logFile, cfg.logLevel, false)
	if err != nil {
		cborplugin.FailStartup("echo-plugin", err)
	}
	serverLog := logBackend.GetLogger("echo_server")
	serverLog.Noticef("Katzenpost echo-plugin version: %s", kpcommon.Version())
	serverLog.Notice("Katzenpost is still pre-alpha.  DO NOT DEPEND ON IT FOR STRONG SECURITY OR ANONYMITY.")

	// start service
	tmpDir, err := os.MkdirTemp("", "echo_server")
	if err != nil {
		cborplugin.FailStartup("echo-plugin", err)
	}
	socketFile := filepath.Join(tmpDir, fmt.Sprintf("%d.echo.socket", os.Getpid()))
	echo := new(Echo)

	var server *cborplugin.Server
	server = cborplugin.NewServer(serverLog, socketFile, new(cborplugin.RequestFactory), echo)
	fmt.Printf("%s\n", socketFile)
	server.Accept()
	server.Wait()
	err = os.Remove(socketFile)
	if err != nil {
		panic(err)
	}
}

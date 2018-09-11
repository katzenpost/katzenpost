// main.go - Crypto currency transaction submition Kaetzchen service plugin program.
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
	"flag"
	"fmt"
	"io"
	"os"
	"path"
	"syscall"

	"github.com/hashicorp/go-plugin"
	common "github.com/katzenpost/server/plugin"
	"github.com/katzenpost/server_plugins/currency/config"
	"github.com/katzenpost/server_plugins/currency/proxy"
	"gopkg.in/op/go-logging.v1"
)

var log = logging.MustGetLogger("currency-go")

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
	leveler.SetLevel(level, "echo-go")
	return leveler
}

func main() {
	var logLevel string
	var logDir string
	cfgFile := flag.String("f", "currency.toml", "Path to the currency config file.")
	flag.StringVar(&logDir, "log_dir", "", "logging directory")
	flag.StringVar(&logLevel, "log_level", "DEBUG", "logging level could be set to: DEBUG, INFO, NOTICE, WARNING, ERROR, CRITICAL")
	flag.Parse()

	// Set the umask to something "paranoid".
	syscall.Umask(0077)

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

	// Load config file.
	cfg, err := config.LoadFile(*cfgFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load config file '%v': %v\n", *cfgFile, err)
		os.Exit(-1)
	}

	// Log to a file.
	level, err := stringToLogLevel(logLevel)
	if err != nil {
		fmt.Println("Invalid logging-level specified.")
		os.Exit(1)
	}
	logFile := path.Join(logDir, fmt.Sprintf("currency-go.%d.log", os.Getpid()))
	f, err := os.Create(logFile)
	logBackend := setupLoggerBackend(level, f)
	log.SetBackend(logBackend)
	log.Debug("currency-go server started.")

	// Start service.
	currency := proxy.New(cfg)
	plugin.Serve(&plugin.ServeConfig{
		HandshakeConfig: common.Handshake,
		Plugins: map[string]plugin.Plugin{
			common.KaetzchenService: &common.KaetzchenPlugin{Impl: currency},
		},

		// A non-nil value here enables gRPC serving for this plugin...
		GRPCServer: plugin.DefaultGRPCServer,
	})
}

// SPDX-FileCopyrightText: © 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"flag"

	"github.com/katzenpost/katzenpost/courier/server"
	"github.com/katzenpost/katzenpost/courier/server/config"
)

func main() {
	var logLevel string
	var logDir string
	var configFile string

	flag.StringVar(&configFile, "c", "", "configuration file")
	flag.StringVar(&logDir, "log_dir", "", "logging directory")
	flag.StringVar(&logLevel, "log_level", "DEBUG", "logging level could be set to: DEBUG, INFO, NOTICE, WARNING, ERROR, CRITICAL")
	flag.Parse()

	// TODO: start listener for storage replica connections
	cfg, err := config.LoadFile(configFile)
	if err != nil {
		panic(err)
	}

	s, err := server.New(cfg)
	if err != nil {
		panic(err)
	}

	// block on listening for the mix server's dialing our unix socket listener
	logBackend := s.LogBackend()
	serverLog := logBackend.GetLogger("courier_service")
	server.StartPlugin(serverLog)
}

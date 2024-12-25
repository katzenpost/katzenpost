// SPDX-FileCopyrightText: © 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"flag"

	"github.com/katzenpost/katzenpost/courier/server"
	"github.com/katzenpost/katzenpost/courier/server/config"
)

func main() {
	var configFile string

	flag.StringVar(&configFile, "c", "", "configuration file")
	flag.Parse()

	cfg, err := config.LoadFile(configFile)
	if err != nil {
		panic(err)
	}

	s, err := server.New(cfg, nil)
	if err != nil {
		panic(err)
	}

	// blocks until service node disconnect
	s.StartPlugin()
}

// SPDX-FileCopyrightText: © 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/carlmjohnson/versioninfo"

	"github.com/katzenpost/katzenpost/courier/server"
	"github.com/katzenpost/katzenpost/courier/server/config"
)

func main() {
	var configFile string
	var printVersion bool

	flag.StringVar(&configFile, "c", "", "configuration file")
	flag.BoolVar(&printVersion, "v", false, "print version and exit")
	flag.Parse()

	if printVersion {
		fmt.Fprintln(os.Stdout, versioninfo.Short())
		os.Exit(0)
	}

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

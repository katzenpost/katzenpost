// SPDX-FileCopyrightText: © 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/carlmjohnson/versioninfo"

	"github.com/katzenpost/katzenpost/common/tomlstrict"
	"github.com/katzenpost/katzenpost/courier/server"
	"github.com/katzenpost/katzenpost/courier/server/config"
)

func main() {
	var configFile string
	var printVersion bool
	var validateOnly bool

	flag.StringVar(&configFile, "c", "", "configuration file")
	flag.BoolVar(&printVersion, "v", false, "print version and exit")
	flag.BoolVar(&validateOnly, "validate-only", false,
		"load and validate the configuration file, then exit without side effects")
	flag.Parse()

	if printVersion {
		fmt.Fprintln(os.Stdout, versioninfo.Short())
		os.Exit(0)
	}

	cfg, err := config.LoadFile(configFile)
	if err != nil {
		if validateOnly {
			fmt.Fprintf(os.Stderr, "configuration file '%v' is invalid: %v\n", configFile, err)
			os.Exit(1)
		}
		panic(err)
	}
	if validateOnly {
		if err := tomlstrict.Check(configFile, new(config.Config)); err != nil {
			fmt.Fprintf(os.Stderr, "configuration file '%v' is invalid: %v\n", configFile, err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stdout, "configuration file '%v' is valid\n", configFile)
		os.Exit(0)
	}

	s, err := server.New(cfg, nil)
	if err != nil {
		panic(err)
	}

	// blocks until service node disconnect
	s.StartPlugin()
}

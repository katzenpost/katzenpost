// SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/carlmjohnson/versioninfo"

	"github.com/katzenpost/katzenpost/core/compat"
	"github.com/katzenpost/katzenpost/replica"
	"github.com/katzenpost/katzenpost/replica/config"
)

func main() {
	cfgFile := flag.String("f", "replica_server.toml", "Path to the replica server config file.")
	genOnly := flag.Bool("g", false, "Generate the keys and exit immediately.")
	version := flag.Bool("v", false, "Get version info.")

	flag.Parse()

	if *version {
		fmt.Printf("version is %s\n", versioninfo.Short())
		return
	}
	if *cfgFile == "" {
		panic("-f must specify a replica server config file location")
	}

	// Set the umask to something "paranoid".
	compat.Umask(0077)

	// Ensure that a sane number of OS threads is allowed.
	if os.Getenv("GOMAXPROCS") == "" {
		// But only if the user isn't trying to override it.
		nProcs := runtime.GOMAXPROCS(0)
		nCPU := runtime.NumCPU()
		if nProcs < nCPU {
			runtime.GOMAXPROCS(nCPU)
		}
	}

	cfg, err := config.LoadFile(*cfgFile, *genOnly)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load server config file '%v': %v\n", *cfgFile, err)
		os.Exit(-1)
	}

	// Setup the signal handling.
	haltCh := make(chan os.Signal)
	signal.Notify(haltCh, os.Interrupt, syscall.SIGTERM)

	rotateCh := make(chan os.Signal)
	signal.Notify(rotateCh, syscall.SIGHUP)

	// Start up the server.
	svr, err := replica.New(cfg)
	if err != nil {
		if err == replica.ErrGenerateOnly {
			os.Exit(0)
		}
		fmt.Fprintf(os.Stderr, "Failed to spawn server instance: %v\n", err)
		os.Exit(-1)
	}
	defer svr.Shutdown()

	// Halt the server gracefully on SIGINT/SIGTERM.
	go func() {
		<-haltCh
		svr.Shutdown()
	}()

	// Rotate server logs upon SIGHUP.
	go func() {
		<-rotateCh
		svr.RotateLog()
	}()

	// Wait for the server to explode or be terminated.
	svr.Wait()
}

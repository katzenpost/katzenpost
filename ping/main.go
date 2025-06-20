// main.go - Katzenpost ping tool
// Copyright (C) 2018, 2019  David Stainton
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
	"os"
	"time"

	"github.com/carlmjohnson/versioninfo"
	"github.com/katzenpost/hpqc/rand"
	"github.com/katzenpost/katzenpost/client2"
	"github.com/katzenpost/katzenpost/client2/config"
	"github.com/katzenpost/katzenpost/client2/thin"
)

const (
	initialPKIConsensusTimeout = 45 * time.Second
)

func randUser() string {
	user := [32]byte{}
	_, err := rand.Reader.Read(user[:])
	if err != nil {
		panic(err)
	}
	return fmt.Sprintf("%x", user[:])
}

// parseFlags handles command line flag parsing and validation
func parseFlags() (configFile, service string, count, concurrency int, printDiff, thinClientOnly bool) {
	var timeout int
	flag.StringVar(&configFile, "c", "", "configuration file")
	flag.StringVar(&service, "s", "", "service name")
	flag.IntVar(&count, "n", 5, "count")
	flag.IntVar(&timeout, "t", 45, "timeout")
	flag.IntVar(&concurrency, "C", 1, "concurrency")
	flag.BoolVar(&printDiff, "printDiff", false, "print payload contents if reply is different than original")
	flag.BoolVar(&thinClientOnly, "thin", false, "use thin client mode (connect to existing daemon)")
	version := flag.Bool("v", false, "Get version info.")
	flag.Parse()

	if *version {
		fmt.Printf("version is %s\n", versioninfo.Short())
		os.Exit(0)
	}

	if service == "" {
		panic("must specify service name with -s")
	}

	return configFile, service, count, concurrency, printDiff, thinClientOnly
}

// initializeClient sets up either thin client or full daemon mode
func initializeClient(configFile string, thinClientOnly bool) (*thin.ThinClient, *client2.Daemon) {
	if thinClientOnly {
		return initializeThinClient(configFile), nil
	}
	return initializeFullClient(configFile)
}

// initializeThinClient sets up thin client mode
func initializeThinClient(configFile string) *thin.ThinClient {
	cfg, err := thin.LoadFile(configFile)
	if err != nil {
		panic(fmt.Errorf("failed to open thin client config: %s", err))
	}

	logging := &config.Logging{
		Disable: false,
		File:    "",
		Level:   "DEBUG",
	}

	thinClient := thin.NewThinClient(cfg, logging)
	err = thinClient.Dial()
	if err != nil {
		panic(fmt.Errorf("failed to connect to daemon: %s", err))
	}
	return thinClient
}

// initializeFullClient sets up full daemon mode
func initializeFullClient(configFile string) (*thin.ThinClient, *client2.Daemon) {
	cfg, err := config.LoadFile(configFile)
	if err != nil {
		panic(fmt.Errorf("failed to open config: %s", err))
	}

	// create a client and connect to the mixnet Gateway
	daemon, err := client2.NewDaemon(cfg)
	if err != nil {
		panic(err)
	}
	err = daemon.Start()
	if err != nil {
		panic(err)
	}

	fmt.Println("Sleeping for 3 seconds to let the client daemon startup...")
	time.Sleep(time.Second * 3)

	thinClient := thin.NewThinClient(thin.FromConfig(cfg), cfg.Logging)
	err = thinClient.Dial()
	if err != nil {
		panic(err)
	}
	return thinClient, daemon
}

// executePing performs the ping operation
func executePing(thinClient *thin.ThinClient, service string, count, concurrency int, printDiff bool) {
	desc, err := thinClient.GetService(service)
	if err != nil {
		panic(err)
	}

	sendPings(thinClient, desc, count, concurrency, printDiff)
}

// cleanup handles daemon shutdown
func cleanup(daemon *client2.Daemon) {
	if daemon != nil {
		daemon.Shutdown()
	}
}

func main() {
	configFile, service, count, concurrency, printDiff, thinClientOnly := parseFlags()
	thinClient, daemon := initializeClient(configFile, thinClientOnly)
	executePing(thinClient, service, count, concurrency, printDiff)
	cleanup(daemon)
}

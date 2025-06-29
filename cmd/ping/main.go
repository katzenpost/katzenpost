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
	"context"
	"fmt"
	"os"
	"time"

	"github.com/carlmjohnson/versioninfo"
	"github.com/charmbracelet/fang"
	"github.com/katzenpost/hpqc/rand"
	"github.com/katzenpost/katzenpost/client2"
	"github.com/katzenpost/katzenpost/client2/config"
	"github.com/katzenpost/katzenpost/client2/thin"
	"github.com/spf13/cobra"
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

// Config holds the command line configuration
type Config struct {
	ConfigFile     string
	Service        string
	Count          int
	Timeout        int
	Concurrency    int
	PrintDiff      bool
	ThinClientOnly bool
}

// newRootCommand creates the root cobra command
func newRootCommand() *cobra.Command {
	var cfg Config

	cmd := &cobra.Command{
		Use:   "ping",
		Short: "Katzenpost mixnet ping tool",
		Long: `A ping tool for testing and debugging Katzenpost mixnet services.

This tool sends test messages to a specified service in the mixnet and measures
the success rate of message delivery. It supports both thin client mode
(connecting to an existing daemon) and full client mode.`,
		Example: `  # Ping the echo service using thin client mode
  ping -c client.toml -s echo --thin

  # Ping with custom count and concurrency
  ping -c client.toml -s echo -n 10 -C 3

  # Show payload differences on mismatch
  ping -c client.toml -s echo --print-diff`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if cfg.Service == "" {
				return fmt.Errorf("must specify service name with -s/--service")
			}

			thinClient, daemon := initializeClient(cfg.ConfigFile, cfg.ThinClientOnly)
			defer cleanup(daemon)

			executePing(thinClient, cfg.Service, cfg.Count, cfg.Concurrency, cfg.PrintDiff)
			return nil
		},
	}

	// Add flags
	cmd.Flags().StringVarP(&cfg.ConfigFile, "config", "c", "", "configuration file")
	cmd.Flags().StringVarP(&cfg.Service, "service", "s", "", "service name")
	cmd.Flags().IntVarP(&cfg.Count, "count", "n", 5, "number of ping messages to send")
	cmd.Flags().IntVarP(&cfg.Timeout, "timeout", "t", 45, "timeout in seconds")
	cmd.Flags().IntVarP(&cfg.Concurrency, "concurrency", "C", 1, "number of concurrent ping operations")
	cmd.Flags().BoolVar(&cfg.PrintDiff, "print-diff", false, "print payload contents if reply is different than original")
	cmd.Flags().BoolVar(&cfg.ThinClientOnly, "thin", false, "use thin client mode (connect to existing daemon)")

	// Mark required flags
	cmd.MarkFlagRequired("service")

	return cmd
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
	rootCmd := newRootCommand()

	// Use fang to execute the command with all its features
	if err := fang.Execute(
		context.Background(),
		rootCmd,
		fang.WithVersion(versioninfo.Short()),
	); err != nil {
		os.Exit(1)
	}
}

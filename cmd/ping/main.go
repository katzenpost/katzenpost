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
	"github.com/katzenpost/katzenpost/common"
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

// getLogFilePath creates a temporary log file with a ping-specific pattern
func getLogFilePath() string {
	// Create a temporary file with a ping-specific pattern
	// The pattern will create files like: /tmp/ping.log.123456.tmp
	tmpFile, err := os.CreateTemp("", "ping.log.*.tmp")
	if err != nil {
		// If we can't create a temp file, fall back to no logging
		return ""
	}

	// Get the file path and close the file (we just want the path)
	logPath := tmpFile.Name()
	tmpFile.Close()

	return logPath
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
	LogLevel       string
}

// newRootCommand creates the root cobra command
func newRootCommand() *cobra.Command {
	var cfg Config

	cmd := &cobra.Command{
		Use:   "ping",
		Short: "Katzenpost mixnet ping tool",
		Long: `A ping tool for testing and debugging Katzenpost mixnet connectivity.

This ping tools sends Sphinx packets destined to the specified service but it's designed to
work with the "echo" mixnet service which replies with the same payload that it receives.
We measure the success rate of Sphinx packet delivery. This ping tool is a mixnet client
and thus supports both thin client mode by connecting to an existing kpclientd daemon and
full client mode where this ping tool starts it's own client daemon.`,
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

			// Print log file location for user reference
			logPath := getLogFilePath()
			if logPath != "" {
				fmt.Printf("Logging to: %s (level: %s)\n", logPath, cfg.LogLevel)
			}

			thinClient, daemon := initializeClient(cfg.ConfigFile, cfg.ThinClientOnly, logPath, cfg.LogLevel)
			defer cleanup(daemon)

			executePing(thinClient, cfg.Service, cfg.Count, cfg.Concurrency, cfg.PrintDiff)
			return nil
		},
	}

	// Add flags
	cmd.Flags().StringVarP(&cfg.ConfigFile, "config", "c", "", "configuration file")
	cmd.Flags().StringVarP(&cfg.Service, "service", "s", "echo", "service name")
	cmd.Flags().IntVarP(&cfg.Count, "count", "n", 5, "number of ping messages to send")
	cmd.Flags().IntVarP(&cfg.Timeout, "timeout", "t", 45, "timeout in seconds")
	cmd.Flags().IntVarP(&cfg.Concurrency, "concurrency", "C", 1, "number of concurrent ping operations")
	cmd.Flags().BoolVar(&cfg.PrintDiff, "print-diff", false, "print payload contents if reply is different than original")
	cmd.Flags().BoolVar(&cfg.ThinClientOnly, "thin", false, "use thin client mode (connect to existing daemon)")
	cmd.Flags().StringVar(&cfg.LogLevel, "log-level", "DEBUG", "logging level (DEBUG, INFO, NOTICE, WARNING, ERROR, CRITICAL)")

	// Mark required flags
	cmd.MarkFlagRequired("service")

	return cmd
}

// initializeClient sets up either thin client or full daemon mode
func initializeClient(configFile string, thinClientOnly bool, logPath string, logLevel string) (*thin.ThinClient, *client2.Daemon) {
	if thinClientOnly {
		return initializeThinClient(configFile, logPath, logLevel), nil
	}
	return initializeFullClient(configFile, logPath, logLevel)
}

// initializeThinClient sets up thin client mode
func initializeThinClient(configFile string, logPath string, logLevel string) *thin.ThinClient {
	cfg, err := thin.LoadFile(configFile)
	if err != nil {
		panic(fmt.Errorf("failed to open thin client config: %s", err))
	}

	logging := &config.Logging{
		Disable: false,
		File:    logPath,
		Level:   logLevel,
	}

	thinClient := thin.NewThinClient(cfg, logging)
	err = thinClient.Dial()
	if err != nil {
		panic(fmt.Errorf("failed to connect to daemon: %s", err))
	}
	return thinClient
}

// initializeFullClient sets up full daemon mode
func initializeFullClient(configFile string, logPath string, logLevel string) (*thin.ThinClient, *client2.Daemon) {
	cfg, err := config.LoadFile(configFile)
	if err != nil {
		panic(fmt.Errorf("failed to open config: %s", err))
	}

	// Override logging configuration to use our log file
	if cfg.Logging == nil {
		cfg.Logging = &config.Logging{}
	}
	cfg.Logging.File = logPath
	cfg.Logging.Level = logLevel
	cfg.Logging.Disable = false

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

	// Use fang to execute the command with enhanced features and custom error handler
	if err := fang.Execute(
		context.Background(),
		rootCmd,
		fang.WithVersion(versioninfo.Short()),
		fang.WithErrorHandler(common.ErrorHandlerWithUsage(rootCmd)),
	); err != nil {
		os.Exit(1)
	}
}

// main.go - Katzenpost
// Copyright (C) 2017  Yawning Angel.
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
	"time"

	"github.com/spf13/cobra"

	"github.com/katzenpost/katzenpost/client2/config"
	"github.com/katzenpost/katzenpost/client2/thin"
	"github.com/katzenpost/katzenpost/common"
)

// Config holds the command line configuration
type Config struct {
	ConfigFile string
	Retry      int
	Delay      int
	LogLevel   string
}

// newRootCommand creates the root cobra command
func newRootCommand() *cobra.Command {
	var cfg Config

	cmd := &cobra.Command{
		Use:   "fetch",
		Short: "Fetch network documents from Katzenpost directory authorities",
		Long: `Fetch and display network topology documents from Katzenpost directory
authorities. This tool connects to the client2 daemon to retrieve the
current network consensus document containing mix node information.

Core functionality:
• Connects to client2 daemon using thin client configuration
• Retrieves current network consensus documents
• Displays network topology and mix node information
• Supports retry logic for robust network document fetching

The tool is useful for network monitoring, debugging connectivity issues,
and inspecting the current state of the mixnet topology.`,
		Example: `  # Fetch network document with default settings
  fetch --config client.toml

  # Fetch with custom retry parameters
  fetch --config client.toml --retry 5 --delay 10

  # Fetch with short flags
  fetch -f client.toml -r 3 -d 5

  # Fetch for network monitoring
  fetch --config /etc/katzenpost/client.toml --retry 1`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runFetch(cfg)
		},
	}

	// Configuration flags
	cmd.Flags().StringVarP(&cfg.ConfigFile, "config", "f", "katzenpost-authority.toml",
		"path to the thin client configuration file (TOML format)")
	cmd.Flags().IntVarP(&cfg.Retry, "retry", "r", 10,
		"number of connection retry attempts")
	cmd.Flags().IntVarP(&cfg.Delay, "delay", "d", 30,
		"seconds to wait between retry attempts")
	cmd.Flags().StringVarP(&cfg.LogLevel, "log_level", "l", "DEBUG",
		"logging level (DEBUG, INFO, NOTICE, WARNING, ERROR, CRITICAL)")

	return cmd
}

func main() {
	rootCmd := newRootCommand()
	common.ExecuteWithFang(rootCmd)
}

// getThinClient connects to the client2 daemon and returns a ThinClient
func getThinClient(cfgFile string, logLevel string, retry int, delay int) (*thin.ThinClient, error) {
	cfg, err := thin.LoadFile(cfgFile)
	if err != nil {
		return nil, err
	}

	logging := &config.Logging{
		Level: logLevel,
	}
	client := thin.NewThinClient(cfg, logging)

	retries := 0
	for {
		err = client.Dial()
		switch err {
		case nil:
			return client, nil
		default:
			if retry >= 0 && retries >= retry {
				return nil, errors.New("failed to connect within retry limit")
			}
			<-time.After(time.Duration(delay) * time.Second)
		}
		retries++
	}
}

// runFetch fetches network documents from directory authorities
func runFetch(cfg Config) error {
	client, err := getThinClient(cfg.ConfigFile, cfg.LogLevel, cfg.Retry, cfg.Delay)
	if err != nil {
		return fmt.Errorf("failed to connect to client2 daemon: %v", err)
	}
	defer client.Close()

	doc := client.PKIDocument()
	if doc != nil {
		// Display the network document
		fmt.Printf("%v", doc)
	} else {
		return fmt.Errorf("no network document available")
	}

	return nil
}

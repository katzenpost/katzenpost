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
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/katzenpost/katzenpost/client2"
	"github.com/katzenpost/katzenpost/client2/config"
	"github.com/katzenpost/katzenpost/common"
	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/core/pki"
)

// Config holds the command line configuration
type Config struct {
	ConfigFile string
	Retry      int
	Delay      int
}

// newRootCommand creates the root cobra command
func newRootCommand() *cobra.Command {
	var cfg Config

	cmd := &cobra.Command{
		Use:   "fetch",
		Short: "Fetch network documents from Katzenpost directory authorities",
		Long: `Fetch and display network topology documents from Katzenpost directory
authorities. This tool connects to the mixnet PKI system to retrieve the
current network consensus document containing mix node information.

Core functionality:
• Connects to directory authorities using client configuration
• Establishes TOFU (Trust On First Use) session for PKI access
• Retrieves current network consensus documents
• Displays network topology and mix node information
• Supports retry logic for robust network document fetching
• Handles epoch timing for document availability

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
		"path to the client configuration file (TOML format)")
	cmd.Flags().IntVarP(&cfg.Retry, "retry", "r", 10,
		"number of connection retry attempts")
	cmd.Flags().IntVarP(&cfg.Delay, "delay", "d", 30,
		"seconds to wait between retry attempts")

	return cmd
}

func main() {
	rootCmd := newRootCommand()
	common.ExecuteWithFang(rootCmd)
}

// runFetch fetches network documents from directory authorities
func runFetch(cfg Config) error {
	clientCfg, err := config.LoadFile(cfg.ConfigFile)
	if err != nil {
		return fmt.Errorf("failed to load config file: %v", err)
	}

	logBackend, err := log.New("", clientCfg.Logging.Level, clientCfg.Logging.Disable)
	if err != nil {
		return fmt.Errorf("failed to create log backend: %v", err)
	}

	cc, err := client2.New(clientCfg, logBackend)
	if err != nil {
		return fmt.Errorf("failed to create client: %v", err)
	}
	defer cc.Shutdown()

	retries := 0
	for {
		err = cc.Start()
		switch err {
		case nil:
			// Success, continue
			goto connected
		case pki.ErrNoDocument:
			// Wait for next epoch
			_, _, till := epochtime.Now()
			<-time.After(till)
		default:
			if retries >= cfg.Retry {
				return fmt.Errorf("failed to connect within retry limit: %v", err)
			}
			<-time.After(time.Duration(cfg.Delay) * time.Second)
		}
		retries++
	}

connected:
	_, doc := cc.CurrentDocument()
	if doc != nil {
		// Display the network document
		fmt.Printf("%v", doc)
	} else {
		return fmt.Errorf("no network document available")
	}

	return nil
}

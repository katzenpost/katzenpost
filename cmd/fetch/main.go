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

	"github.com/spf13/cobra"

	"github.com/katzenpost/katzenpost/client2/config"
	"github.com/katzenpost/katzenpost/client2/thin"
	"github.com/katzenpost/katzenpost/common"
)

// Config holds the command line configuration
type Config struct {
	ConfigFile string
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
• Retries until PKI document becomes available

The tool is useful for network monitoring, debugging connectivity issues,
and inspecting the current state of the mixnet topology.`,
		Example: `  # Fetch network document with default settings
  fetch --config thinclient.toml

  # Fetch with short flags
  fetch -f thinclient.toml`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runFetch(cfg)
		},
	}

	// Configuration flags
	cmd.Flags().StringVarP(&cfg.ConfigFile, "config", "f", "thinclient.toml",
		"path to the thin client configuration file (TOML format)")
	cmd.Flags().StringVarP(&cfg.LogLevel, "log_level", "l", "DEBUG",
		"logging level (DEBUG, INFO, NOTICE, WARNING, ERROR, CRITICAL)")

	return cmd
}

func main() {
	rootCmd := newRootCommand()
	common.ExecuteWithFang(rootCmd)
}

// runFetch fetches network documents from directory authorities
func runFetch(cfg Config) error {
	thinCfg, err := thin.LoadFile(cfg.ConfigFile)
	if err != nil {
		return fmt.Errorf("failed to load config file: %v", err)
	}

	logging := &config.Logging{
		Level: cfg.LogLevel,
	}
	client := thin.NewThinClient(thinCfg, logging)
	defer client.Close()

	// Connect to the daemon
	err = client.Dial()
	if err != nil {
		return fmt.Errorf("failed to connect to client2 daemon: %v", err)
	}

	// Check if we already have a PKI document
	doc := client.PKIDocument()
	if doc != nil {
		fmt.Printf("%v", doc)
		return nil
	}

	// Wait for PKI document via event sink
	eventSink := client.EventSink()
	defer client.StopEventSink(eventSink)

	for {
		select {
		case event := <-eventSink:
			if docEvent, ok := event.(*thin.NewDocumentEvent); ok {
				fmt.Printf("%v", docEvent.Document)
				return nil
			}
		case <-client.HaltCh():
			return fmt.Errorf("connection closed before receiving PKI document")
		}
	}
}

// main.go - Katzenpost server binary.
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
	"context"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/carlmjohnson/versioninfo"
	"github.com/charmbracelet/fang"
	"github.com/spf13/cobra"

	"github.com/katzenpost/katzenpost/core/compat"
	"github.com/katzenpost/katzenpost/server"
	"github.com/katzenpost/katzenpost/server/config"
)

// Config holds the command line configuration
type Config struct {
	ConfigFile string
	GenOnly    bool
}

// newRootCommand creates the root cobra command
func newRootCommand() *cobra.Command {
	var cfg Config

	cmd := &cobra.Command{
		Use:   "server",
		Short: "Katzenpost mixnet server node",
		Long: `The Katzenpost server is a mixnet node that provides anonymous communication
services as part of the Katzenpost decentralized anonymous communication network.

The server operates as one of three possible roles in the mix network:
1. A mix node
2. A gateway node
3. A service node

When operating as a mix node, it functions as a standard
mix node in the network topology, performing packet
mixing, routing, and relay services. It connects to other mix nodes and
directory authorities to participate in the mixnet infrastructure.

Key features:
• Supports one of three roles: mix node, gateway node, or service node
• Sphinx (Classical and Post quantum) packet mixing for traffic analysis resistance
• Decoy traffic generation to obscure communication patterns
• Integration with directory authority services, updating its mix descriptor
  and participating in the network's PKI (Public Key Infrastructure) by uploading
  a new MixDescriptor every epoch.
• Cryptographic key management and rotation. Rotates mix keys every epoch.
• Real-time network status monitoring
• Implements the continuous time mixing strategy and delays packets for the
  time duration specified by the "Delay" Sphinx routing command.

The server is designed to run as a long-lived daemon process and requires
proper configuration for network participation, cryptographic keys, and
operational parameters.`,
		Example: `  # Start server with default configuration
  server

  # Start server with custom configuration file
  server --config /etc/katzenpost/server.toml

  # Start server with specific config file (short form)
  server -f /path/to/custom-config.toml

  # Generate cryptographic keys only and exit (useful for setup)
  server --generate-only

  # Generate keys with custom config and exit
  server -f /etc/katzenpost/server.toml --generate-only

  # Start server with environment variable override
  KATZENPOST_CONFIG=/opt/katzenpost/server.toml server

  # Run server in foreground with verbose logging
  server --config /etc/katzenpost/server.toml --log-level debug

  # Validate configuration without starting server
  server --config /etc/katzenpost/server.toml --validate-only`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runServer(cfg)
		},
	}

	// Configuration flags
	cmd.Flags().StringVarP(&cfg.ConfigFile, "config", "f", "katzenpost.toml",
		"path to the server configuration file (TOML format)")

	// Operation mode flags
	cmd.Flags().BoolVarP(&cfg.GenOnly, "generate-only", "g", false,
		"generate cryptographic keys and exit without starting server")

	return cmd
}

func main() {
	rootCmd := newRootCommand()

	// Use fang to execute the command with enhanced features including automatic man page generation
	if err := fang.Execute(
		context.Background(),
		rootCmd,
		fang.WithVersion(versioninfo.Short()),
	); err != nil {
		os.Exit(1)
	}
}

func runServer(cfg Config) error {
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

	serverCfg, err := config.LoadFile(cfg.ConfigFile)
	if err != nil {
		return fmt.Errorf("failed to load config file '%v': %v", cfg.ConfigFile, err)
	}
	if cfg.GenOnly && !serverCfg.Debug.GenerateOnly {
		serverCfg.Debug.GenerateOnly = true
	}

	// Setup the signal handling.
	haltCh := make(chan os.Signal, 1)
	signal.Notify(haltCh, os.Interrupt, syscall.SIGTERM)

	rotateCh := make(chan os.Signal, 1)
	signal.Notify(rotateCh, syscall.SIGHUP)

	// Start up the server.
	svr, err := server.New(serverCfg)
	if err != nil {
		if err == server.ErrGenerateOnly {
			return nil // Exit successfully for generate-only mode
		}
		return fmt.Errorf("failed to spawn server instance: %v", err)
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
	return nil
}

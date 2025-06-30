// main.go - Katzenpost voting-authority binary.
// Copyright (C) 2023  Yawning Angel, Masala
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
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/katzenpost/katzenpost/authority/voting/server"
	"github.com/katzenpost/katzenpost/authority/voting/server/config"
	"github.com/katzenpost/katzenpost/common"
	"github.com/katzenpost/katzenpost/core/compat"
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
		Use:   "dirauth",
		Short: "Katzenpost directory authority server",
		Long: `The Katzenpost directory authority implements a voting-based PKI (Public Key
Infrastructure) for the mixnet. It coordinates with other authorities to
establish network consensus and publish a new PKI document every epoch.

Core responsibilities:
• Maintains authoritative network routing topology
• Coordinates voting rounds with other directory authorities for consensus
• Publishes signed PKI documents containing mix descriptors and keys
• Validates mix descriptor uploads and key rotations
• Enforces network policies and operational parameters
• Provides PKI services for secure authentication with our PQ Noise based transport

The authority operates in a distributed voting system where multiple authorities
must reach consensus before publishing network documents. This ensures no single
authority can compromise the network's security or availability.`,
		Example: `  # Start authority with default configuration
  dirauth

  # Start authority with custom configuration file
  dirauth --config /etc/katzenpost/authority.toml

  # Start authority with specific config file (short form)
  dirauth -f /path/to/custom-authority.toml

  # Generate cryptographic keys only and exit (useful for setup)
  dirauth --generate-only

  # Generate keys with custom config and exit
  dirauth -f /etc/katzenpost/authority.toml --generate-only`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runAuthority(cfg)
		},
	}

	// Configuration flags
	cmd.Flags().StringVarP(&cfg.ConfigFile, "config", "f", "katzenpost-authority.toml",
		"path to the authority configuration file (TOML format)")

	// Operation mode flags
	cmd.Flags().BoolVarP(&cfg.GenOnly, "generate-only", "g", false,
		"generate cryptographic keys and exit without starting authority")

	return cmd
}

func main() {
	rootCmd := newRootCommand()
	common.ExecuteWithFang(rootCmd)
}

// runAuthority starts the directory authority server
func runAuthority(cfg Config) error {
	// Set the umask to something "paranoid".
	compat.Umask(0077)

	authorityCfg, err := config.LoadFile(cfg.ConfigFile, cfg.GenOnly)
	if err != nil {
		return fmt.Errorf("failed to load config file '%v': %v", cfg.ConfigFile, err)
	}

	// Setup the signal handling.
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM)

	rotateCh := make(chan os.Signal, 1)
	signal.Notify(rotateCh, syscall.SIGHUP)

	// Start up the authority.
	svr, err := server.New(authorityCfg)
	if err != nil {
		if err == server.ErrGenerateOnly {
			return nil // Exit successfully for generate-only mode
		}
		return fmt.Errorf("failed to spawn authority instance: %v", err)
	}
	defer svr.Shutdown()

	// Halt the authority gracefully on SIGINT/SIGTERM.
	go func() {
		<-ch
		svr.Shutdown()
	}()

	// Rotate server logs upon SIGHUP.
	go func() {
		<-rotateCh
		svr.RotateLog()
	}()

	// Wait for the authority to explode or be terminated.
	svr.Wait()
	return nil
}

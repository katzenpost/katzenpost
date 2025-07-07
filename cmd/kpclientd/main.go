// SPDX-FileCopyrightText: © 2023 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

// standalone client daemon
package main

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/katzenpost/katzenpost/client2"
	"github.com/katzenpost/katzenpost/client2/config"
	"github.com/katzenpost/katzenpost/common"
)

// Config holds the command line configuration
type Config struct {
	ConfigFile string
}

// newRootCommand creates the root cobra command
func newRootCommand() *cobra.Command {
	var cfg Config

	cmd := &cobra.Command{
		Use:   "kpclientd",
		Short: "Katzenpost client daemon",
		Long: `The Katzenpost client daemon allows multiple client applications
to send and receive messages through the mixnet. It maintains connections to the
network, handles all the mixnet cryptography, Sphinx packet route selection,
retransmissions, and SURB reply handling. Client applications connect to the
daemon using a thin client library which provides a simple API for sending and
receiving messages.

Core functionality:
• Maintains persistent connections to gateway nodes and directory authorities
• Handles automatic key rotation and network topology updates
• Manages message queuing, retry logic, and delivery confirmations
• Implements decoy traffic generation for traffic analysis resistance
• Supports both reliable and unreliable message delivery modes

The daemon is designed to run as a background service, allowing multiple client
applications to share a single network connection.`,
		Example: `
  # Start daemon with configuration file
  kpclientd --config /etc/katzenpost/client.toml

  # Start daemon with specific config file (short form)
  kpclientd -c /path/to/custom-client.toml`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runClientDaemon(cfg)
		},
	}

	// Configuration flags
	cmd.Flags().StringVarP(&cfg.ConfigFile, "config", "c", "",
		"path to the client configuration file (TOML format)")

	// Mark required flags
	cmd.MarkFlagRequired("config")

	return cmd
}

func main() {
	rootCmd := newRootCommand()
	common.ExecuteWithFang(rootCmd)
}

// runClientDaemon starts the client daemon
func runClientDaemon(cfg Config) error {
	haltCh := make(chan os.Signal, 1)
	signal.Notify(haltCh, os.Interrupt, syscall.SIGTERM)

	clientCfg, err := config.LoadFile(cfg.ConfigFile)
	if err != nil {
		return fmt.Errorf("failed to load config file: %v", err)
	}

	d, err := client2.NewDaemon(clientCfg)
	if err != nil {
		return fmt.Errorf("failed to create daemon: %v", err)
	}

	err = d.Start()
	if err != nil {
		return fmt.Errorf("failed to start daemon: %v", err)
	}
	defer d.Shutdown()

	go func() {
		<-haltCh
		d.Shutdown()
	}()

	d.Wait()
	return nil
}

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

	"github.com/katzenpost/katzenpost/client"
	"github.com/katzenpost/katzenpost/client/config"
	"github.com/katzenpost/katzenpost/client/instrument"
	"github.com/katzenpost/katzenpost/common"
	"github.com/katzenpost/katzenpost/common/tomlstrict"
)

// Config holds the command line configuration
type Config struct {
	ConfigFile   string
	ValidateOnly bool
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
  kpclientd -c /path/to/custom-client.toml

  # Validate the configuration file and exit without side effects
  kpclientd -c /etc/katzenpost/client.toml --validate-only`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runClientDaemon(cfg)
		},
	}

	// Configuration flags
	cmd.Flags().StringVarP(&cfg.ConfigFile, "config", "c", "",
		"path to the client configuration file (TOML format)")

	// Operation mode flags
	cmd.Flags().BoolVar(&cfg.ValidateOnly, "validate-only", false,
		"load and validate the configuration file, then exit without side effects")

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
	if cfg.ValidateOnly {
		if err := tomlstrict.Check(cfg.ConfigFile, new(config.Config)); err != nil {
			return fmt.Errorf("config file '%v': %v", cfg.ConfigFile, err)
		}
		fmt.Fprintf(os.Stdout, "configuration file '%v' is valid\n", cfg.ConfigFile)
		return nil
	}

	// Start the prometheus listener before the daemon so that any
	// startup-time emissions are captured. When the build tag
	// `kpclientd_metrics` is not set the call is a no-op and incurs
	// no listener; production builds therefore expose no /metrics
	// surface regardless of whether the config field is populated.
	instrument.StartPrometheusListener(clientCfg.MetricsAddress)

	d, err := client.NewDaemon(clientCfg)
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

// SPDX-FileCopyrightText: © 2023 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

// standalone client daemon
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/katzenpost/katzenpost/client"
	"github.com/katzenpost/katzenpost/client/config"
	"github.com/katzenpost/katzenpost/client/instrument"
	"github.com/katzenpost/katzenpost/common"
	"github.com/katzenpost/katzenpost/common/tomlstrict"
)

const exampleDBusName = "network.katzenpost.kpclientd"

// Config holds the command line configuration
type Config struct {
	ConfigFile   string
	ValidateOnly bool
	DBusName     string
	DBusNameSet  bool
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
  kpclientd -c /etc/katzenpost/client.toml --validate-only

  # Own a session dbus name for the daemon's lifetime
  kpclientd -c /etc/katzenpost/client.toml --dbus-name network.katzenpost.kpclientd`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg.DBusNameSet = cmd.Flags().Changed("dbus-name")
			return runClientDaemon(cfg)
		},
	}

	// Configuration flags
	cmd.Flags().StringVarP(&cfg.ConfigFile, "config", "c", "",
		"path to the client configuration file (TOML format)")

	// Operation mode flags
	cmd.Flags().BoolVar(&cfg.ValidateOnly, "validate-only", false,
		"load and validate the configuration file, then exit without side effects")
	cmd.Flags().StringVar(&cfg.DBusName, "dbus-name", "",
		"own this session dbus name for the daemon's lifetime, for example "+exampleDBusName+"; the name means a running daemon rather than a ready listener, and an empty value disables a configured name")

	// Mark required flags
	cmd.MarkFlagRequired("config")

	return cmd
}

func main() {
	rootCmd := newRootCommand()
	common.ExecuteWithFang(rootCmd)
}

// runClientDaemon starts the client daemon
const dbusOwnTimeout = 10 * time.Second

func runClientDaemon(cfg Config) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	clientCfg, err := config.LoadFile(cfg.ConfigFile)
	if err != nil {
		return fmt.Errorf("failed to load config file: %v", err)
	}
	if cfg.DBusName != "" {
		if err := config.ValidateDBusName(cfg.DBusName); err != nil {
			return err
		}
	}
	if cfg.ValidateOnly {
		if err := tomlstrict.Check(cfg.ConfigFile, new(config.Config)); err != nil {
			return fmt.Errorf("config file '%v': %v", cfg.ConfigFile, err)
		}
		fmt.Fprintf(os.Stdout, "configuration file '%v' is valid\n", cfg.ConfigFile)
		return nil
	}
	bus, err := ownConfiguredDBusName(ctx, cfg, clientCfg)
	if err != nil {
		return err
	}
	if bus != nil {
		defer func() {
			if err := bus.Close(); err != nil {
				fmt.Fprintf(os.Stderr, "releasing dbus name: %v\n", err)
			}
		}()
	}

	// Start the prometheus listener before the daemon so that any
	// startup-time emissions are captured. When the build tag
	// `kpclientd_metrics` is not set the call is a no-op and incurs
	// no listener; production builds therefore expose no /metrics
	// surface regardless of whether the config field is populated.
	instrument.StartPrometheusListener(clientCfg.MetricsAddress, nil)

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
		<-ctx.Done()
		d.Shutdown()
	}()

	d.Wait()
	return nil
}

func ownConfiguredDBusName(ctx context.Context, cfg Config, clientCfg *config.Config) (io.Closer, error) {
	name := clientCfg.DBusName
	if cfg.DBusNameSet {
		name = cfg.DBusName
	}
	if name == "" {
		return nil, nil
	}
	ownCtx, cancel := context.WithTimeout(ctx, dbusOwnTimeout)
	defer cancel()
	bus, err := ownBusName(ownCtx, name)
	switch {
	case errors.Is(err, errNameConflict):
		return nil, fmt.Errorf("failed to own dbus name %q: %w", name, err)
	case errors.Is(err, context.Canceled):
		return nil, nil
	case err != nil:
		fmt.Fprintf(os.Stderr, "not owning dbus name %q: %v\n", name, err)
		return nil, nil
	}
	return bus, nil
}

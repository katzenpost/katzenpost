// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"fmt"
	"os"
	"time"

	"github.com/katzenpost/katzenpost/client2"
	"github.com/katzenpost/katzenpost/client2/config"
	"github.com/katzenpost/katzenpost/client2/thin"
)

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
		fmt.Fprintf(os.Stderr, "Failed to open thin client config: %s\n", err)
		os.Exit(1)
	}

	logging := &config.Logging{
		Disable: false,
		File:    "",
		Level:   "ERROR",
	}

	thinClient := thin.NewThinClient(cfg, logging)
	err = thinClient.Dial()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to connect to daemon: %s\n", err)
		os.Exit(1)
	}
	return thinClient
}

// initializeFullClient sets up full daemon mode
func initializeFullClient(configFile string) (*thin.ThinClient, *client2.Daemon) {
	cfg, err := config.LoadFile(configFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to open config: %s\n", err)
		os.Exit(1)
	}

	// Suppress logging for cleaner output
	if cfg.Logging == nil {
		cfg.Logging = &config.Logging{}
	}
	cfg.Logging.Disable = true

	// Create a client and connect to the mixnet Gateway
	daemon, err := client2.NewDaemon(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to create daemon: %s\n", err)
		os.Exit(1)
	}
	err = daemon.Start()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to start daemon: %s\n", err)
		os.Exit(1)
	}

	// Wait for daemon to initialize
	fmt.Fprintln(os.Stderr, "Waiting for client daemon to initialize...")
	time.Sleep(time.Second * 3)

	thinClient := thin.NewThinClient(thin.FromConfig(cfg), cfg.Logging)
	err = thinClient.Dial()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to connect to daemon: %s\n", err)
		daemon.Shutdown()
		os.Exit(1)
	}
	return thinClient, daemon
}

// cleanup handles daemon and client shutdown
func cleanup(daemon *client2.Daemon, thinClient *thin.ThinClient) {
	if thinClient != nil {
		thinClient.Close()
	}
	if daemon != nil {
		daemon.Shutdown()
	}
}


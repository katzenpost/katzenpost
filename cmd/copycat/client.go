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

const (
	// daemonReadinessTimeout is the maximum time to wait for the daemon to become ready
	daemonReadinessTimeout = 60 * time.Second
	// daemonReadinessInterval is how often to check if the daemon is ready
	daemonReadinessInterval = 500 * time.Millisecond
)

// initializeClient sets up either thin client or full daemon mode with default logging
func initializeClient(configFile string, thinClientOnly bool) (*thin.ThinClient, *client2.Daemon) {
	return initializeClientWithLogging(configFile, thinClientOnly, "ERROR")
}

// initializeClientWithLogging sets up either thin client or full daemon mode with configurable logging
func initializeClientWithLogging(configFile string, thinClientOnly bool, logLevel string) (*thin.ThinClient, *client2.Daemon) {
	if thinClientOnly {
		return initializeThinClientWithLogging(configFile, logLevel), nil
	}
	return initializeFullClientWithLogging(configFile, logLevel)
}

// initializeThinClientWithLogging sets up thin client mode with configurable logging
func initializeThinClientWithLogging(configFile string, logLevel string) *thin.ThinClient {
	cfg, err := thin.LoadFile(configFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to open thin client config: %s\n", err)
		os.Exit(1)
	}

	logging := &config.Logging{
		Disable: false,
		File:    "",
		Level:   logLevel,
	}

	thinClient := thin.NewThinClient(cfg, logging)
	err = thinClient.Dial()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to connect to daemon: %s\n", err)
		os.Exit(1)
	}
	return thinClient
}

// initializeFullClientWithLogging sets up full daemon mode with configurable logging
func initializeFullClientWithLogging(configFile string, logLevel string) (*thin.ThinClient, *client2.Daemon) {
	cfg, err := config.LoadFile(configFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to open config: %s\n", err)
		os.Exit(1)
	}

	// Configure logging based on user preference
	if cfg.Logging == nil {
		cfg.Logging = &config.Logging{}
	}
	cfg.Logging.Level = logLevel
	cfg.Logging.Disable = logLevel == ""

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

	// Wait for daemon to become ready using actual readiness probe
	fmt.Fprintln(os.Stderr, "Waiting for client daemon to initialize...")
	thinClient, err := waitForDaemonReady(cfg, logLevel)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to connect to daemon: %s\n", err)
		daemon.Shutdown()
		os.Exit(1)
	}

	return thinClient, daemon
}

// waitForDaemonReady polls the daemon until it accepts connections and reports ready
func waitForDaemonReady(cfg *config.Config, logLevel string) (*thin.ThinClient, error) {
	deadline := time.Now().Add(daemonReadinessTimeout)

	logging := &config.Logging{
		Disable: logLevel == "",
		File:    "",
		Level:   logLevel,
	}

	for time.Now().Before(deadline) {
		thinClient := thin.NewThinClient(thin.FromConfig(cfg), logging)
		err := thinClient.Dial()
		if err == nil {
			// Successfully connected - check if daemon is connected to mixnet
			if thinClient.IsConnected() {
				fmt.Fprintln(os.Stderr, "Daemon is connected to mixnet")
				return thinClient, nil
			}
			// Connected but not yet connected to mixnet - this is acceptable
			// for offline mode or if connection will happen later
			fmt.Fprintln(os.Stderr, "Daemon started (offline mode)")
			return thinClient, nil
		}

		// Connection failed - wait and retry
		time.Sleep(daemonReadinessInterval)
	}

	return nil, fmt.Errorf("daemon did not become ready within %v", daemonReadinessTimeout)
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

// SPDX-FileCopyrightText: Copyright (C) 2025 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/katzenpost/katzenpost/common"
	"github.com/katzenpost/katzenpost/core/compat"
	"github.com/katzenpost/katzenpost/replica"
	"github.com/katzenpost/katzenpost/replica_service"
	"github.com/katzenpost/katzenpost/replica_service/config"
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
		Use:   "replica",
		Short: "Katzenpost replica storage service (not replica storage server!)",
		Long: `The Katzenpost replica storage service provides data storage and replication
services for the mixnet. We never interact with replicas directly, instead all our interactions
are mediated through the courier service. The courier service is responsible for proxying
queries and replies to and from the storage replica services. The replica services perform their replication
and communication with the courier services inside of the mixnet (unlike the replica storage servers which operate
outside the mixnet).

Core functionality:
* key value store where the keys are BACAP Box ID's, also known as public keys,
however since we are using BACAP, these are blinded public keys.
* performs replication based on our hash based sharding scheme
* replies to service queries which presumably originate from the courier services
* maintains knowledge of the latest mixnet PKI document
* maintains knowledge of other replicas storage services for replication

BACAP source code: https://github.com/katzenpost/hpqc/blob/master/bacap/
BACAP golang documentation: https://pkg.go.dev/github.com/katzenpost/hpqc/bacap

We recommend reading about BACAP in section 4 of our paper
if you want to know more about the blinding and unlinkability
properties of the system and the cryptographic deterministic addressing
scheme for message boxes.

We also recommend reading about the Pigeonhole storage system
in section 5. Our mixnet paper can be found on arXiv:

**Echomix: a Strong Anonymity System with Messaging**
https://arxiv.org/abs/2501.02933

The replica server is designed for deployments where various protocols
are being composed that will use the pigeonhole storage system along with
BACAP for addressing and message encryption.
`,
		Example: `  # Start replica server with default configuration
  replica

  # Start replica server with custom configuration file
  replica_service --config /etc/katzenpost/replica_service.toml

  # Start replica server with specific config file (short form)
  replica_service -f /path/to/custom-replica_service.toml

  # Generate cryptographic keys only and exit (useful for setup)
  replica --generate-only

  # Generate keys with custom config and exit
  replica -f /etc/katzenpost/replica.toml --generate-only`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runReplicaService(cfg)
		},
		SilenceErrors: true,
		SilenceUsage:  true,
	}

	// Configuration flags
	cmd.Flags().StringVarP(&cfg.ConfigFile, "config", "f", "replica_server.toml",
		"path to the replica server configuration file (TOML format)")

	// Operation mode flags
	cmd.Flags().BoolVarP(&cfg.GenOnly, "generate-only", "g", false,
		"generate cryptographic keys and exit without starting server")

	return cmd
}

func main() {
	rootCmd := newRootCommand()
	common.ExecuteWithFang(rootCmd)
}

// runReplicaServer starts the replica server
func runReplicaService(cfg Config) error {
	if cfg.ConfigFile == "" {
		return fmt.Errorf("config file must be specified")
	}

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

	replicaCfg, err := config.LoadFile(cfg.ConfigFile, cfg.GenOnly)
	if err != nil {
		return fmt.Errorf("failed to load server config file '%v': %v", cfg.ConfigFile, err)
	}

	// Setup the signal handling.
	haltCh := make(chan os.Signal, 1)
	signal.Notify(haltCh, os.Interrupt, syscall.SIGTERM)

	rotateCh := make(chan os.Signal, 1)
	signal.Notify(rotateCh, syscall.SIGHUP)

	// Start up the server.
	svr, err := replica_service.New(replicaCfg)
	if err != nil {
		if err == replica.ErrGenerateOnly {
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

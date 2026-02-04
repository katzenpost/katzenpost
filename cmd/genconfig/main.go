// SPDX-FileCopyrightText: Copyright (C) 2022  Yawning Angel, David Stainton, Masala
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"github.com/spf13/cobra"

	"github.com/katzenpost/katzenpost/common"
	"github.com/katzenpost/katzenpost/core/genconfig"
)

func main() {
	rootCmd := newRootCommand()
	common.ExecuteWithFang(rootCmd)
}

// newRootCommand creates the root cobra command
func newRootCommand() *cobra.Command {
	var cfg genconfig.Config

	cmd := &cobra.Command{
		Use:   "genconfig",
		Short: "Generate Katzenpost mixnet configuration files",
		Long: `Generate comprehensive configuration files for a Katzenpost mixnet deployment.
This tool creates all necessary configuration files for directory authorities,
mix nodes, gateway nodes, service nodes, storage replicas, and client configurations.

Core functionality:
• Generates voting directory authority configurations with PKI consensus
• Creates mix node configurations for packet forwarding through the network
• Configures gateway nodes for client connections and traffic ingress/egress
• Sets up service nodes with plugins for storage, HTTP proxy, and other services
• Generates storage replica configurations for the Pigeonhole storage system
• Creates client configurations for both legacy and modern client implementations
• Produces Docker Compose files for easy deployment and testing
• Generates Prometheus monitoring configurations for network metrics

The tool supports both classical and post-quantum cryptographic schemes,
configurable network topologies, and comprehensive parameter tuning for
performance optimization and security requirements.`,
		Example: `  # Generate basic voting mixnet with default settings
  genconfig --voting --wirekem MLKEM768 --nike x25519 --baseDir /tmp/mixnet --outDir ./configs

  # Generate larger network with custom parameters
  genconfig --voting --nrVoting 5 --layers 5 --nodes 15 --gateways 3 \
    --serviceNodes 2 --storageNodes 7 --wirekem MLKEM768 --nike x25519 \
    --baseDir /opt/katzenpost --outDir ./production-configs

  # Generate test network with post-quantum KEM for Sphinx
  genconfig --voting --wirekem MLKEM768 --kem MLKEM768 \
    --baseDir /tmp/test --outDir ./test-configs --dockerImage katzenpost:latest

  # Generate network with custom timing parameters
  genconfig --voting --wirekem MLKEM768 --nike x25519 \
    --mu 0.01 --lP 0.002 --lM 0.1 --baseDir /tmp/mixnet --outDir ./configs`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return genconfig.RunGenConfig(cfg)
		},
	}

	// Network topology flags
	cmd.Flags().IntVarP(&cfg.NrLayers, "layers", "L", genconfig.NrLayers,
		"number of mix layers in the network topology")
	cmd.Flags().IntVarP(&cfg.NrNodes, "nodes", "n", genconfig.NrNodes,
		"number of mix nodes to generate")
	cmd.Flags().IntVar(&cfg.NrGateways, "gateways", genconfig.NrGateways,
		"number of gateway nodes for client connections")
	cmd.Flags().IntVar(&cfg.NrServiceNodes, "serviceNodes", genconfig.NrServiceNodes,
		"number of service nodes with plugins (storage, HTTP proxy, etc.)")
	cmd.Flags().IntVar(&cfg.NrStorageNodes, "storageNodes", genconfig.NrStorageNodes,
		"number of storage replica nodes for Pigeonhole system")

	// Authority and voting flags
	cmd.Flags().BoolVarP(&cfg.Voting, "voting", "v", false,
		"generate voting directory authority configuration")
	cmd.Flags().IntVar(&cfg.NrVoting, "nrVoting", genconfig.NrAuthorities,
		"number of voting directory authorities to generate")
	cmd.Flags().BoolVarP(&cfg.OmitTopology, "dynamic", "D", false,
		"use dynamic topology (omit fixed topology definition)")

	// Directory and deployment flags
	cmd.Flags().StringVarP(&cfg.BaseDir, "baseDir", "b", "",
		"base directory path for runtime data and configurations")
	cmd.Flags().StringVarP(&cfg.OutDir, "outDir", "o", "",
		"output directory path for generated configuration files")
	cmd.Flags().IntVarP(&cfg.BasePort, "port", "P", genconfig.BasePort,
		"starting port number for network services")
	cmd.Flags().StringVarP(&cfg.BindAddr, "addr", "a", genconfig.BindAddr,
		"IP address to bind network services to")

	// Docker and deployment flags
	cmd.Flags().StringVarP(&cfg.DockerImage, "dockerImage", "d", "katzenpost-go_mod",
		"Docker image name for docker-compose.yml generation")
	cmd.Flags().StringVarP(&cfg.BinSuffix, "binSuffix", "S", "",
		"suffix for binary names in docker-compose.yml")

	// Cryptographic scheme flags
	cmd.Flags().StringVar(&cfg.Wirekem, "wirekem", "",
		"KEM scheme for wire protocol (required, e.g., MLKEM768, XWING)")
	cmd.Flags().StringVar(&cfg.Kem, "kem", "",
		"KEM scheme for Sphinx packet encryption (e.g., MLKEM768, FrodoKEM-640-SHAKE)")
	cmd.Flags().StringVar(&cfg.Nike, "nike", "x25519",
		"NIKE scheme for Sphinx packet encryption (e.g., x25519, x448)")
	cmd.Flags().StringVar(&cfg.PkiSignatureScheme, "pkiScheme", "ed25519",
		"PKI signature scheme for authentication (e.g., ed25519, dilithium2)")

	// Sphinx and payload flags
	cmd.Flags().IntVar(&cfg.UserForwardPayloadLength, "UserForwardPayloadLength", 2000,
		"user forward payload length in bytes for Sphinx packets")

	// Traffic and timing flags
	cmd.Flags().BoolVar(&cfg.NoDecoy, "noDecoy", true,
		"disable decoy traffic generation for clients")
	cmd.Flags().BoolVar(&cfg.NoMixDecoy, "noMixDecoy", true,
		"disable decoy traffic generation for mix nodes")
	cmd.Flags().IntVar(&cfg.DialTimeout, "dialTimeout", 0,
		"session dial timeout in seconds (0 for default)")
	cmd.Flags().IntVar(&cfg.MaxPKIDelay, "maxPKIDelay", 0,
		"initial maximum PKI retrieval delay in seconds (0 for default)")
	cmd.Flags().IntVar(&cfg.PollingIntvl, "pollingIntvl", 0,
		"PKI polling interval in seconds (0 for default)")

	// Advanced timing parameters
	cmd.Flags().Uint64Var(&cfg.Sr, "sendRate", 0,
		"client send rate limit per minute (0 for unlimited)")
	cmd.Flags().Float64Var(&cfg.Mu, "mu", 0.005,
		"inverse of mean per-hop delay (higher = faster)")
	cmd.Flags().Uint64Var(&cfg.MuMax, "muMax", 1000,
		"maximum delay for mu parameter in milliseconds")
	cmd.Flags().Float64Var(&cfg.LP, "lambdaP", 0.001,
		"inverse of mean client send rate (higher = more frequent)")
	cmd.Flags().Uint64Var(&cfg.LPMax, "lambdaPMax", 1000,
		"maximum delay for lambdaP in milliseconds")
	cmd.Flags().Float64Var(&cfg.LL, "lambdaL", 0.0005,
		"inverse of mean loop decoy send rate")
	cmd.Flags().Uint64Var(&cfg.LLMax, "lambdaLMax", 1000,
		"maximum delay for lambdaL in milliseconds")
	cmd.Flags().Float64Var(&cfg.LD, "lambdaD", 0.0005,
		"inverse of mean drop decoy send rate")
	cmd.Flags().Uint64Var(&cfg.LDMax, "lambdaDMax", 3000,
		"maximum delay for lambdaD in milliseconds")
	cmd.Flags().Float64Var(&cfg.LM, "lambdaM", 0.2,
		"inverse of mean mix decoy send rate")
	cmd.Flags().Uint64Var(&cfg.LMMax, "lambdaMMax", 100,
		"maximum delay for lambdaM in milliseconds")
	cmd.Flags().Uint64Var(&cfg.LGMax, "lambdaGMax", 100,
		"maximum delay for gateway lambda in milliseconds")

	// Logging flags
	cmd.Flags().StringVar(&cfg.LogLevel, "logLevel", genconfig.DebugLogLevel,
		"logging level (DEBUG, INFO, NOTICE, WARNING, ERROR, CRITICAL)")

	// Mark required flags
	cmd.MarkFlagRequired("wirekem")
	cmd.MarkFlagRequired("baseDir")
	cmd.MarkFlagRequired("outDir")

	return cmd
}

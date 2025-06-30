// SPDX-FileCopyrightText: Copyright (C) 2025  David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"fmt"
	"os"

	"github.com/carlmjohnson/versioninfo"
	"github.com/charmbracelet/fang"
	"github.com/spf13/cobra"

	kempem "github.com/katzenpost/hpqc/kem/pem"
	kemschemes "github.com/katzenpost/hpqc/kem/schemes"
	nikepem "github.com/katzenpost/hpqc/nike/pem"
	nikeschemes "github.com/katzenpost/hpqc/nike/schemes"
	signpem "github.com/katzenpost/hpqc/sign/pem"
	signschemes "github.com/katzenpost/hpqc/sign/schemes"

	"github.com/katzenpost/katzenpost/common"
github.com/katzenpost/katzenpost/core/utils
)

const (
	writingKeypairFormat = "Writing keypair to %s and %s\n"
	errBothKeysExist     = "both keys already exist"
	errOneKeyExists      = "one of the keys already exists"
)

func validateArgs(keyType, schemeName, outName string) {
	if keyType == "" {
		panic("type cannot be empty")
	}
	if schemeName == "" {
		panic("scheme cannot be empty")
	}
	if outName == "" {
		panic("out cannot be empty")
	}
}

func checkKeyFilesExist(privout, pubout string) {
	fmt.Printf(writingKeypairFormat, pubout, privout)

	switch {
	case utils.BothExists(privout, pubout):
		panic(errBothKeysExist)
	case utils.BothNotExists(privout, pubout):
		return
	default:
		panic(errOneKeyExists)
	}
}

func generateKemKeypair(schemeName, outName string) {
	pubout := fmt.Sprintf("%s.kem_public.pem", outName)
	privout := fmt.Sprintf("%s.kem_private.pem", outName)

	checkKeyFilesExist(privout, pubout)

	scheme := kemschemes.ByName(schemeName)
	pubkey, privkey, err := scheme.GenerateKeyPair()
	if err != nil {
		panic(err)
	}

	if err := kempem.PublicKeyToFile(pubout, pubkey); err != nil {
		panic(err)
	}
	if err := kempem.PrivateKeyToFile(privout, privkey); err != nil {
		panic(err)
	}
}

func generateNikeKeypair(schemeName, outName string) {
	pubout := fmt.Sprintf("%s.nike_public.pem", outName)
	privout := fmt.Sprintf("%s.nike_private.pem", outName)

	checkKeyFilesExist(privout, pubout)

	scheme := nikeschemes.ByName(schemeName)
	pubkey, privkey, err := scheme.GenerateKeyPair()
	if err != nil {
		panic(err)
	}

	if err := nikepem.PublicKeyToFile(pubout, pubkey, scheme); err != nil {
		panic(err)
	}
	if err := nikepem.PrivateKeyToFile(privout, privkey, scheme); err != nil {
		panic(err)
	}
}

func generateSignKeypair(schemeName, outName string) {
	pubout := fmt.Sprintf("%s.sign_public.pem", outName)
	privout := fmt.Sprintf("%s.sign_private.pem", outName)

	checkKeyFilesExist(privout, pubout)

	scheme := signschemes.ByName(schemeName)
	pubkey, privkey, err := scheme.GenerateKey()
	if err != nil {
		panic(err)
	}

	if err := signpem.PublicKeyToFile(pubout, pubkey); err != nil {
		panic(err)
	}
	if err := signpem.PrivateKeyToFile(privout, privkey); err != nil {
		panic(err)
	}
}

// Config holds the command line configuration
type Config struct {
	KeyType    string
	SchemeName string
	OutName    string
}

// newRootCommand creates the root cobra command
func newRootCommand() *cobra.Command {
	var cfg Config

	cmd := &cobra.Command{
		Use:   "genkeypair",
		Short: "Generate cryptographic key pairs",
		Long: `Generate cryptographic key pairs for Katzenpost mixnet components.
Supports generating NIKE (Non-Interactive Key Exchange), KEM (Key Encapsulation
Mechanism), and digital signature key pairs using various cryptographic schemes.

Supported key types:
• NIKE: Non-Interactive Key Exchange keys for Sphinx packet encryption
• KEM: Key Encapsulation Mechanism keys for post-quantum cryptography
• Sign: Digital signature keys for authentication and integrity

The tool generates both private and public key files in PEM format, which can
be used by Katzenpost servers, clients, and other network components.`,
		Example: `  # Generate X25519 NIKE key pair (default)
  genkeypair --type nike --scheme x25519 --out server_nike

  # Generate Kyber768 KEM key pair for post-quantum security
  genkeypair --type kem --scheme kyber768 --out server_kem

  # Generate Ed25519 signature key pair
  genkeypair --type sign --scheme ed25519 --out server_sign

  # Generate key pair with short flags
  genkeypair -t kem -s kyber1024 -o authority_kem

  # Generate default key pair (X25519 NIKE)
  genkeypair --out my_keys`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runGenKeypair(cfg)
		},
	}

	// Key generation flags
	cmd.Flags().StringVarP(&cfg.KeyType, "type", "t", "kem",
		"cryptographic key type (nike, kem, sign)")
	cmd.Flags().StringVarP(&cfg.SchemeName, "scheme", "s", "x25519",
		"cryptographic scheme name")
	cmd.Flags().StringVarP(&cfg.OutName, "out", "o", "out",
		"output file name prefix for key pair")

	return cmd
}

func main() {
	rootCmd := newRootCommand()

	// Use fang to execute the command with enhanced features and custom error handler
	if err := fang.Execute(
		context.Background(),
		rootCmd,
		fang.WithVersion(versioninfo.Short()),
		fang.WithErrorHandler(common.ErrorHandlerWithUsage(rootCmd)),
	); err != nil {
		os.Exit(1)
	}
}

// runGenKeypair generates the specified key pair
func runGenKeypair(cfg Config) error {
	validateArgs(cfg.KeyType, cfg.SchemeName, cfg.OutName)

	switch cfg.KeyType {
	case "kem":
		generateKemKeypair(cfg.SchemeName, cfg.OutName)
	case "nike":
		generateNikeKeypair(cfg.SchemeName, cfg.OutName)
	case "sign":
		generateSignKeypair(cfg.SchemeName, cfg.OutName)
	default:
		return fmt.Errorf("key type must be kem, nike or sign, got: %s", cfg.KeyType)
	}
	return nil
}

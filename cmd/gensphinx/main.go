// SPDX-FileCopyrightText: Copyright (C) 2022  Yawning Angel, David Stainton, Masala
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"charm.land/lipgloss/v2"
	"github.com/carlmjohnson/versioninfo"
	"github.com/charmbracelet/colorprofile"
	"github.com/charmbracelet/fang"
	"github.com/spf13/cobra"

	"github.com/katzenpost/qrterminal"

	kemschemes "github.com/katzenpost/hpqc/kem/schemes"
	"github.com/katzenpost/hpqc/nike/schemes"

	"github.com/katzenpost/katzenpost/core/sphinx/geo"
)

const defaultNrLayers = 3

// Config holds the command line configuration
type Config struct {
	NrLayers                 int
	KEM                      string
	NIKE                     string
	UserForwardPayloadLength int
	QRCode                   bool
}

// newRootCommand creates the root cobra command
func newRootCommand() *cobra.Command {
	var cfg Config

	cmd := &cobra.Command{
		Use:   "gensphinx",
		Short: "Generate Sphinx packet geometry configurations",
		Long: `The gensphinx tool generates and displays Sphinx packet geometry configurations
for mixnet communication. It calculates the precise packet sizes, header lengths,
and payload capacities based on the specified cryptographic schemes and network topology.

Core functionality:
• Generate geometry for NIKE (Non-Interactive Key Exchange) schemes like X25519
• Generate geometry for KEM (Key Encapsulation Mechanism) schemes for post-quantum security
• Calculate packet sizes for specified number of mix layers and hops
• Display detailed geometry information including header sizes and payload lengths
• Optional QR code output for easy sharing of geometry configurations

The tool supports both classical and post-quantum cryptographic schemes, allowing
network operators to plan and configure mixnets with appropriate packet sizes
for their security requirements.`,
		Example: `  # Generate geometry for X25519 with default settings
  gensphinx --nike x25519

  # Generate geometry for Kyber KEM with custom payload size
  gensphinx --kem Xwing --payload-length 1500

  # Generate geometry with custom layer count and QR code output
  gensphinx --nike x25519 --layers 5 --payload-length 2000 --qr

  # Generate geometry for post-quantum KEM scheme
  gensphinx --kem kyber1024 --layers 3 --payload-length 1024`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runGenSphinx(cfg)
		},
	}

	// Configuration flags
	cmd.Flags().IntVarP(&cfg.NrLayers, "layers", "L", defaultNrLayers,
		"number of mix layers in the network topology")
	cmd.Flags().StringVar(&cfg.KEM, "kem", "",
		"name of the KEM (Key Encapsulation Mechanism) scheme to use (e.g., kyber768, kyber1024)")
	cmd.Flags().StringVar(&cfg.NIKE, "nike", "x25519",
		"name of the NIKE (Non-Interactive Key Exchange) scheme to use (e.g., x25519)")
	cmd.Flags().IntVar(&cfg.UserForwardPayloadLength, "payload-length", 2000,
		"maximum user forward payload length in bytes")
	cmd.Flags().BoolVarP(&cfg.QRCode, "qr", "q", false,
		"output the geometry configuration as a QR code to stdout")

	return cmd
}

// errorHandlerWithUsage creates a custom error handler that displays error messages
// followed by usage help for CLI argument errors. This provides better user experience
// by showing both the error and how to use the command correctly.
func errorHandlerWithUsage(cmd *cobra.Command) fang.ErrorHandler {
	return func(w io.Writer, styles fang.Styles, err error) {
		// Print the styled error header and message
		_, _ = fmt.Fprintln(w, styles.ErrorHeader.String())
		_, _ = fmt.Fprintln(w, styles.ErrorText.Render(err.Error()+"."))
		_, _ = fmt.Fprintln(w)

		// Check if this is a usage error that should show help
		if isUsageError(err) {
			// Print the usage help
			helpFunc := cmd.HelpFunc()
			if helpFunc != nil {
				// Create a colorprofile writer for the help output
				_ = colorprofile.NewWriter(w, nil)
				helpFunc(cmd, []string{})
			}
		} else {
			// For non-usage errors, just show the "Try --help" suggestion
			_, _ = fmt.Fprintln(w, lipgloss.JoinHorizontal(
				lipgloss.Left,
				styles.ErrorText.UnsetWidth().Render("Try"),
				styles.Program.Flag.Render("--help"),
				styles.ErrorText.UnsetWidth().UnsetMargins().UnsetTransform().PaddingLeft(1).Render("for usage."),
			))
			_, _ = fmt.Fprintln(w)
		}
	}
}

// isUsageError determines if an error should trigger usage help display
func isUsageError(err error) bool {
	if err == nil {
		return false
	}
	errStr := strings.ToLower(err.Error())
	return strings.Contains(errStr, "unknown flag") ||
		strings.Contains(errStr, "unknown command") ||
		strings.Contains(errStr, "invalid argument") ||
		strings.Contains(errStr, "required flag") ||
		strings.Contains(errStr, "accepts") ||
		strings.Contains(errStr, "usage")
}

func main() {
	rootCmd := newRootCommand()
	if err := fang.Execute(
		context.Background(),
		rootCmd,
		fang.WithVersion(versioninfo.Short()),
		fang.WithErrorHandler(errorHandlerWithUsage(rootCmd)),
	); err != nil {
		os.Exit(1)
	}
}

// runGenSphinx generates and displays the Sphinx geometry
func runGenSphinx(cfg Config) error {
	nrHops := cfg.NrLayers + 2

	var sphinxGeometry *geo.Geometry

	if cfg.NIKE != "" {
		nikeScheme := schemes.ByName(cfg.NIKE)
		if nikeScheme == nil {
			return fmt.Errorf("failed to resolve NIKE scheme %s", cfg.NIKE)
		}
		sphinxGeometry = geo.GeometryFromUserForwardPayloadLength(
			nikeScheme,
			cfg.UserForwardPayloadLength,
			true,
			nrHops,
		)
	}
	if cfg.KEM != "" {
		kemScheme := kemschemes.ByName(cfg.KEM)
		if kemScheme == nil {
			return fmt.Errorf("failed to resolve KEM scheme %s", cfg.KEM)
		}
		sphinxGeometry = geo.KEMGeometryFromUserForwardPayloadLength(
			kemScheme,
			cfg.UserForwardPayloadLength,
			true,
			nrHops,
		)
	}

	if sphinxGeometry == nil {
		return fmt.Errorf("no valid cryptographic scheme specified; use either --nike or --kem")
	}

	fmt.Printf("\n%s\n\n", sphinxGeometry.Display())

	if cfg.QRCode {
		config := qrterminal.Config{
			Level:      qrterminal.L,
			Writer:     os.Stdout,
			HalfBlocks: true,
			QuietZone:  1,
		}

		qrterminal.GenerateWithConfig(sphinxGeometry.Display(), config)
	}

	return nil
}

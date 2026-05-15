// SPDX-FileCopyrightText: Copyright (C) 2022  Yawning Angel, David Stainton, Masala
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"context"
	"fmt"
	"os"

	"github.com/BurntSushi/toml"
	"github.com/carlmjohnson/versioninfo"
	"github.com/charmbracelet/fang"
	"github.com/spf13/cobra"

	"github.com/katzenpost/qrterminal"

	kemschemes "github.com/katzenpost/hpqc/kem/schemes"
	nikeschemes "github.com/katzenpost/hpqc/nike/schemes"

	sphinxgeo "github.com/katzenpost/katzenpost/core/sphinx/geo"
	pgeo "github.com/katzenpost/katzenpost/pigeonhole/geo"
	replicaCommon "github.com/katzenpost/katzenpost/replica/common"
)

// defaultNrLayers is the conventional mix layer count. The number of
// Sphinx hops is the number of mix layers plus the gateway and the
// service node.
const defaultNrLayers = 3

func main() {
	rootCmd := newRootCommand()
	if err := fang.Execute(
		context.Background(),
		rootCmd,
		fang.WithVersion(versioninfo.Short()),
	); err != nil {
		os.Exit(1)
	}
}

func newRootCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "geometry",
		Short: "Generate Katzenpost geometry configurations",
		Long: `The geometry tool computes the packet and storage geometries that the
mixnet components must agree on, emitting them as TOML tables ready to
paste into a configuration file.

It has two subcommands:

  sphinx      compute a Sphinx packet geometry from cryptographic and
              topology parameters

  pigeonhole  compute a Pigeonhole storage geometry, either from a
              desired box payload size (also emitting an accommodating
              Sphinx geometry) or from an existing Sphinx geometry`,
	}
	cmd.AddCommand(newSphinxCommand(), newPigeonholeCommand())
	return cmd
}

// sphinxConfig holds the flags of the `sphinx` subcommand.
type sphinxConfig struct {
	NrLayers                 int
	KEM                      string
	NIKE                     string
	UserForwardPayloadLength int
	QRCode                   bool
}

func newSphinxCommand() *cobra.Command {
	var cfg sphinxConfig

	cmd := &cobra.Command{
		Use:   "sphinx",
		Short: "Generate a Sphinx packet geometry",
		Long: `Calculate the Sphinx packet sizes, header lengths, and payload
capacities for the given cryptographic schemes and network topology,
and print the result as a [SphinxGeometry] TOML table.

Supply exactly one of --nike or --kem.`,
		Example: `  # X25519 with default settings
  geometry sphinx --nike x25519

  # A post-quantum KEM with a custom payload size
  geometry sphinx --kem Xwing --payload-length 1500 --layers 5`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runSphinx(cfg)
		},
	}

	cmd.Flags().IntVarP(&cfg.NrLayers, "layers", "L", defaultNrLayers,
		"number of mix layers in the network topology")
	cmd.Flags().StringVar(&cfg.KEM, "kem", "",
		"name of the KEM scheme to use (e.g. Xwing, MLKEM768)")
	cmd.Flags().StringVar(&cfg.NIKE, "nike", "x25519",
		"name of the NIKE scheme to use (e.g. x25519)")
	cmd.Flags().IntVar(&cfg.UserForwardPayloadLength, "payload-length", 2000,
		"maximum user forward payload length in bytes")
	cmd.Flags().BoolVarP(&cfg.QRCode, "qr", "q", false,
		"also emit the geometry as a QR code to stdout")

	return cmd
}

// runSphinx builds a Sphinx geometry from cryptographic and topology
// parameters and prints it.
func runSphinx(cfg sphinxConfig) error {
	if (cfg.KEM == "") == (cfg.NIKE == "") {
		return fmt.Errorf("specify exactly one of --nike or --kem")
	}

	nrHops := cfg.NrLayers + 2
	var sphinxGeometry *sphinxgeo.Geometry

	if cfg.NIKE != "" {
		nikeScheme := nikeschemes.ByName(cfg.NIKE)
		if nikeScheme == nil {
			return fmt.Errorf("failed to resolve NIKE scheme %s", cfg.NIKE)
		}
		sphinxGeometry = sphinxgeo.GeometryFromUserForwardPayloadLength(
			nikeScheme, cfg.UserForwardPayloadLength, true, nrHops)
	} else {
		kemScheme := kemschemes.ByName(cfg.KEM)
		if kemScheme == nil {
			return fmt.Errorf("failed to resolve KEM scheme %s", cfg.KEM)
		}
		sphinxGeometry = sphinxgeo.KEMGeometryFromUserForwardPayloadLength(
			kemScheme, cfg.UserForwardPayloadLength, true, nrHops)
	}

	fmt.Printf("\n%s\n", sphinxGeometry.Display())
	return emitQR(cfg.QRCode, sphinxGeometry.Display())
}

// pigeonholeConfig holds the flags of the `pigeonhole` subcommand.
type pigeonholeConfig struct {
	BoxPayloadLength int
	SphinxGeometry   string
	NrLayers         int
	QRCode           bool
}

func newPigeonholeCommand() *cobra.Command {
	var cfg pigeonholeConfig

	cmd := &cobra.Command{
		Use:   "pigeonhole",
		Short: "Generate a Pigeonhole storage geometry",
		Long: `Compute the Pigeonhole geometry that the thin client and the storage
replicas must agree on, emitting it as a [PigeonholeGeometry] TOML
table ready to paste into a thinclient.toml.

It operates in one of two mutually exclusive modes:

1. --box-payload-length: given a desired maximum plaintext box payload,
   compute the Pigeonhole geometry and an accommodating Sphinx geometry,
   and print both TOML tables.

2. --sphinx-geometry: given an existing Sphinx geometry TOML file (the
   output of "geometry sphinx"), derive the Pigeonhole geometry that
   fits within it and print that table alone.

The Pigeonhole geometry uses the replica MKEM NIKE scheme; it is not a
free parameter and is fixed to match the storage replicas.`,
		Example: `  # Mode 1: size everything from a desired box payload.
  geometry pigeonhole --box-payload-length 1553

  # Mode 2: derive the Pigeonhole geometry to fit a Sphinx geometry.
  geometry sphinx --nike x25519 > sphinx.toml
  geometry pigeonhole --sphinx-geometry sphinx.toml`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runPigeonhole(cfg)
		},
	}

	cmd.Flags().IntVar(&cfg.BoxPayloadLength, "box-payload-length", 0,
		"mode 1: desired maximum plaintext box payload length in bytes")
	cmd.Flags().StringVar(&cfg.SphinxGeometry, "sphinx-geometry", "",
		"mode 2: path to a Sphinx geometry TOML file to derive from")
	cmd.Flags().IntVarP(&cfg.NrLayers, "layers", "L", defaultNrLayers,
		"mode 1: number of mix layers, used to size the Sphinx geometry")
	cmd.Flags().BoolVarP(&cfg.QRCode, "qr", "q", false,
		"also emit the Pigeonhole geometry as a QR code to stdout")

	return cmd
}

// runPigeonhole dispatches to the selected mode after validating that
// exactly one was requested.
func runPigeonhole(cfg pigeonholeConfig) error {
	haveBox := cfg.BoxPayloadLength > 0
	haveSphinx := cfg.SphinxGeometry != ""

	switch {
	case haveBox && haveSphinx:
		return fmt.Errorf("--box-payload-length and --sphinx-geometry are mutually exclusive")
	case haveBox:
		return runPigeonholeFromBoxPayload(cfg)
	case haveSphinx:
		return runPigeonholeFromSphinxGeometry(cfg)
	default:
		return fmt.Errorf("specify exactly one of --box-payload-length or --sphinx-geometry")
	}
}

// runPigeonholeFromBoxPayload implements mode 1: a desired box payload
// yields both the Pigeonhole geometry and an accommodating Sphinx
// geometry.
func runPigeonholeFromBoxPayload(cfg pigeonholeConfig) error {
	pigeonGeo := pgeo.NewGeometry(cfg.BoxPayloadLength, replicaCommon.NikeScheme)
	if err := pigeonGeo.Validate(); err != nil {
		return fmt.Errorf("invalid geometry for box payload %d: %w",
			cfg.BoxPayloadLength, err)
	}

	nrHops := cfg.NrLayers + 2
	sphinxGeo := pigeonGeo.ToSphinxGeometry(nrHops, true)

	fmt.Printf("\n%s\n%s\n", sphinxGeo.Display(), pigeonGeo.Display())
	return emitQR(cfg.QRCode, pigeonGeo.Display())
}

// runPigeonholeFromSphinxGeometry implements mode 2: an existing Sphinx
// geometry yields the Pigeonhole geometry that fits within it.
func runPigeonholeFromSphinxGeometry(cfg pigeonholeConfig) error {
	var wrapper struct {
		SphinxGeometry *sphinxgeo.Geometry
	}
	if _, err := toml.DecodeFile(cfg.SphinxGeometry, &wrapper); err != nil {
		return fmt.Errorf("reading Sphinx geometry %q: %w", cfg.SphinxGeometry, err)
	}
	if wrapper.SphinxGeometry == nil {
		return fmt.Errorf("%q has no [SphinxGeometry] table", cfg.SphinxGeometry)
	}

	pigeonGeo, err := pgeo.NewGeometryFromSphinx(wrapper.SphinxGeometry, replicaCommon.NikeScheme)
	if err != nil {
		return fmt.Errorf("deriving Pigeonhole geometry: %w", err)
	}
	if err := pigeonGeo.Validate(); err != nil {
		return fmt.Errorf("derived geometry failed validation: %w", err)
	}

	fmt.Printf("\n%s\n", pigeonGeo.Display())
	return emitQR(cfg.QRCode, pigeonGeo.Display())
}

// emitQR optionally renders the given geometry TOML as a QR code.
func emitQR(want bool, payload string) error {
	if !want {
		return nil
	}
	qrterminal.GenerateWithConfig(payload, qrterminal.Config{
		Level:      qrterminal.L,
		Writer:     os.Stdout,
		HalfBlocks: true,
		QuietZone:  1,
	})
	return nil
}

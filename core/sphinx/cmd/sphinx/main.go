// SPDX-FileCopyrightText: Copyright (C) 2025  David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	kemschemes "github.com/katzenpost/hpqc/kem/schemes"
	"github.com/katzenpost/hpqc/nike/schemes"

	"github.com/katzenpost/katzenpost/core/sphinx/geo"
)

type CreateGeometry struct {
	NrMixHops                int
	NIKE                     string
	KEM                      string
	UserForwardPayloadLength int
	File                     string
}

func printUsage() {
	fmt.Fprintf(os.Stderr, "Usage: %s <subcommand> [options]\n\n", os.Args[0])
	fmt.Fprintf(os.Stderr, "Available subcommands:\n")
	fmt.Fprintf(os.Stderr, "  createGeometry    Generate Sphinx geometry configuration\n")
	fmt.Fprintf(os.Stderr, "  newpacket         Create a new Sphinx packet (not implemented)\n")
	fmt.Fprintf(os.Stderr, "  unwrap            Unwrap a Sphinx packet (not implemented)\n")
	fmt.Fprintf(os.Stderr, "  newsurb           Create a new SURB (not implemented)\n")
	fmt.Fprintf(os.Stderr, "  newpacketfromsurb Create packet from SURB (not implemented)\n")
	fmt.Fprintf(os.Stderr, "\nUse '%s <subcommand> -h' for help on a specific subcommand.\n", os.Args[0])
}

func main() {
	// Show usage if no arguments provided
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	// Handle global help flags
	if os.Args[1] == "-h" || os.Args[1] == "--help" || os.Args[1] == "help" {
		printUsage()
		os.Exit(0)
	}

	var createGeometry CreateGeometry
	newGeoCmd := flag.NewFlagSet("createGeometry", flag.ExitOnError)
	newGeoCmd.IntVar(&createGeometry.NrMixHops, "nrMixLayers", 3, "number of hops per route not counting ingress/egress nodes")
	newGeoCmd.StringVar(&createGeometry.KEM, "kem", "", "Name of the KEM Scheme to be used with Sphinx")
	newGeoCmd.StringVar(&createGeometry.NIKE, "nike", "x25519", "Name of the NIKE Scheme to be used with Sphinx")
	newGeoCmd.IntVar(&createGeometry.UserForwardPayloadLength, "UserForwardPayloadLength", 2000, "UserForwardPayloadLength")
	newGeoCmd.StringVar(&createGeometry.File, "file", "", "file path to write TOML output to, empty indicates stdout")

	// Set custom usage for the createGeometry subcommand
	newGeoCmd.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s createGeometry [options]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Generate Sphinx geometry configuration.\n\n")
		fmt.Fprintf(os.Stderr, "Options:\n")
		newGeoCmd.PrintDefaults()
	}

	switch os.Args[1] {
	case "createGeometry":
		newGeoCmd.Parse(os.Args[2:])
		generateSphinxGeometry(&createGeometry)
	case "newpacket":
		fmt.Fprintf(os.Stderr, "Error: 'newpacket' subcommand is not implemented yet\n")
		os.Exit(1)
	case "unwrap":
		fmt.Fprintf(os.Stderr, "Error: 'unwrap' subcommand is not implemented yet\n")
		os.Exit(1)
	case "newsurb":
		fmt.Fprintf(os.Stderr, "Error: 'newsurb' subcommand is not implemented yet\n")
		os.Exit(1)
	case "newpacketfromsurb":
		fmt.Fprintf(os.Stderr, "Error: 'newpacketfromsurb' subcommand is not implemented yet\n")
		os.Exit(1)
	default:
		fmt.Fprintf(os.Stderr, "Error: unknown subcommand '%s'\n\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func generateSphinxGeometry(createGeometry *CreateGeometry) {
	nrHops := createGeometry.NrMixHops + 2
	var sphinxGeometry *geo.Geometry
	if createGeometry.NIKE != "" {
		nikeScheme := schemes.ByName(createGeometry.NIKE)
		if nikeScheme == nil {
			log.Fatalf("failed to resolve nike scheme %s", createGeometry.NIKE)
		}
		sphinxGeometry = geo.GeometryFromUserForwardPayloadLength(
			nikeScheme,
			createGeometry.UserForwardPayloadLength,
			true,
			nrHops,
		)
	}
	if createGeometry.KEM != "" {
		kemScheme := kemschemes.ByName(createGeometry.KEM)
		if kemScheme == nil {
			log.Fatalf("failed to resolve kem scheme %s", createGeometry.KEM)
		}
		sphinxGeometry = geo.KEMGeometryFromUserForwardPayloadLength(
			kemScheme,
			createGeometry.UserForwardPayloadLength,
			true,
			nrHops,
		)
	}
	tomlOut := sphinxGeometry.Display()
	if createGeometry.File == "" {
		fmt.Println(tomlOut)
	} else {
		out, err := os.OpenFile(createGeometry.File, os.O_WRONLY|os.O_CREATE, 0600)
		if err != nil {
			panic(err)
		}
		writeCount, err := out.Write([]byte(tomlOut))
		if err != nil {
			panic(err)
		}
		if writeCount != len(tomlOut) {
			panic("partial write failure")
		}
		err = out.Sync()
		if err != nil {
			panic(err)
		}
		err = out.Close()
		if err != nil {
			panic(err)
		}
	}
}

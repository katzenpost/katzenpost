// SPDX-FileCopyrightText: Copyright (C) 2022  Yawning Angel, David Stainton, Masala
// SPDX-License-Identifier: AGPL-3.0-only

package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/katzenpost/qrterminal"

	kemschemes "github.com/katzenpost/hpqc/kem/schemes"
	"github.com/katzenpost/hpqc/nike/schemes"
	"github.com/katzenpost/hpqc/rand"

	"github.com/katzenpost/katzenpost/core/sphinx/geo"
)

const nrLayers = 3

func main() {
	nrLayers := flag.Int("L", nrLayers, "Number of mix layers.")
	kem := flag.String("kem", "", "Name of the KEM Scheme to be used with Sphinx")
	nike := flag.String("nike", "x25519", "Name of the NIKE Scheme to be used with Sphinx")
	UserForwardPayloadLength := flag.Int("UserForwardPayloadLength", 2000, "UserForwardPayloadLength")
	isQRCode := flag.Bool("q", false, "print to stdout as QR code")
	flag.Parse()

	nrHops := *nrLayers + 2

	var sphinxGeometry *geo.Geometry

	if *nike != "" {
		nikeScheme := schemes.ByName(*nike)
		if nikeScheme == nil {
			log.Fatalf("failed to resolve nike scheme %s", *nike)
		}
		sphinxGeometry = geo.GeometryFromUserForwardPayloadLength(
			nikeScheme,
			*UserForwardPayloadLength,
			true,
			nrHops,
		)
	}
	if *kem != "" {
		kemScheme := kemschemes.ByName(*kem)
		if kemScheme == nil {
			log.Fatalf("failed to resolve kem scheme %s", *kem)
		}
		sphinxGeometry = geo.KEMGeometryFromUserForwardPayloadLength(
			kemScheme,
			*UserForwardPayloadLength,
			true,
			nrHops,
		)
	}

	fmt.Printf("\n%s\n\n", sphinxGeometry.Display())

	if *isQRCode {
		config := qrterminal.Config{
			Level:      qrterminal.L,
			Writer:     os.Stdout,
			HalfBlocks: true,
			QuietZone:  1,
		}

		blob := make([]byte, 1000)
		_, err := rand.Reader.Read(blob)
		if err != nil {
			panic(err)
		}
		qrterminal.GenerateWithConfig(sphinxGeometry.Display(), config)
	}
}

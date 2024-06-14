// SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-or-later

package sphinx

import (
	"testing"

	kemSchemes "github.com/katzenpost/hpqc/kem/schemes"
	nikeSchemes "github.com/katzenpost/hpqc/nike/schemes"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
)

func TestDisplaySphinxGeometries(t *testing.T) {
	tests := []struct {
		name        string
		isNIKE      bool
		nikeName    string
		kemName     string
		payloadSize int
		nrHops      int
	}{
		// NIKEs
		{
			name:        "X25519 NIKE",
			isNIKE:      true,
			nikeName:    "x25519",
			kemName:     "",
			nrHops:      5,
			payloadSize: 2000,
		},
		{
			name:        "X448 NIKE",
			isNIKE:      true,
			nikeName:    "x448",
			kemName:     "",
			nrHops:      5,
			payloadSize: 2000,
		},
		{
			name:        "CTIDH512-X25519 PQ Hybrid NIKE",
			isNIKE:      true,
			nikeName:    "CTIDH512-X25519",
			kemName:     "",
			nrHops:      5,
			payloadSize: 2000,
		},

		// NIKEs adapted as KEMs (via adhoc hashed elgamal construction)
		{
			name:        "X25519 KEM",
			isNIKE:      false,
			nikeName:    "",
			kemName:     "x25519",
			nrHops:      5,
			payloadSize: 2000,
		},
		{
			name:        "X448 KEM",
			isNIKE:      false,
			nikeName:    "",
			kemName:     "x448",
			nrHops:      5,
			payloadSize: 2000,
		},

		// more KEMs
		{
			name:        "Xwing KEM",
			isNIKE:      false,
			nikeName:    "",
			kemName:     "Xwing",
			nrHops:      5,
			payloadSize: 2000,
		},
		{
			name:        "MLKEM768-X25519 KEM",
			isNIKE:      false,
			nikeName:    "",
			kemName:     "MLKEM768-X25519",
			nrHops:      5,
			payloadSize: 2000,
		},
	}

	for i := 0; i < len(tests); i++ {
		t.Run(tests[i].name, func(t *testing.T) {
			if tests[i].isNIKE {
				scheme := nikeSchemes.ByName(tests[i].nikeName)
				g := geo.GeometryFromUserForwardPayloadLength(scheme, tests[i].payloadSize, false, tests[i].nrHops)
				t.Logf("HeaderLength: %d, PacketLength: %d", g.HeaderLength, g.PacketLength)
			} else { // KEM
				scheme := kemSchemes.ByName(tests[i].kemName)
				g := geo.KEMGeometryFromUserForwardPayloadLength(scheme, tests[i].payloadSize, false, tests[i].nrHops)
				t.Logf("HeaderLength: %d, PacketLength: %d", g.HeaderLength, g.PacketLength)
			}
		})
	}
}

func TestDisplaySphinxGeometryRanges(t *testing.T) {
	tests := []struct {
		name        string
		isNIKE      bool
		nikeName    string
		kemName     string
		payloadSize int
		startHop    int
		endHop      int
	}{
		// NIKEs
		{
			name:        "X25519 NIKE",
			isNIKE:      true,
			nikeName:    "x25519",
			kemName:     "",
			payloadSize: 2000,
			startHop:    6,
			endHop:      10,
		},
		{
			name:        "X448 NIKE",
			isNIKE:      true,
			nikeName:    "x448",
			kemName:     "",
			payloadSize: 2000,
			startHop:    6,
			endHop:      10,
		},
		{
			name:        "CTIDH512-X25519 PQ Hybrid NIKE",
			isNIKE:      true,
			nikeName:    "CTIDH512-X25519",
			kemName:     "",
			payloadSize: 2000,
			startHop:    6,
			endHop:      10,
		},

		// NIKEs adapted as KEMs (via adhoc hashed elgamal construction)
		{
			name:        "X25519 KEM",
			isNIKE:      false,
			nikeName:    "",
			kemName:     "x25519",
			payloadSize: 2000,
			startHop:    6,
			endHop:      10,
		},
		{
			name:        "X448 KEM",
			isNIKE:      false,
			nikeName:    "",
			kemName:     "x448",
			payloadSize: 2000,
			startHop:    6,
			endHop:      10,
		},

		// more KEMs
		{
			name:        "Xwing KEM",
			isNIKE:      false,
			nikeName:    "",
			kemName:     "Xwing",
			payloadSize: 2000,
			startHop:    6,
			endHop:      10,
		},
		{
			name:        "MLKEM768-X25519 KEM",
			isNIKE:      false,
			nikeName:    "",
			kemName:     "MLKEM768-X25519",
			payloadSize: 2000,
			startHop:    6,
			endHop:      10,
		},
	}

	for i := 0; i < len(tests); i++ {
		t.Run(tests[i].name, func(t *testing.T) {
			if tests[i].isNIKE {
				for j := tests[i].startHop; j < tests[i].endHop; j++ {
					scheme := nikeSchemes.ByName(tests[i].nikeName)
					g := geo.GeometryFromUserForwardPayloadLength(scheme, tests[i].payloadSize, false, j)
					t.Logf("Hops: %d, HeaderLength: %d, PacketLength: %d", j, g.HeaderLength, g.PacketLength)
				}
			} else { // KEM
				for j := tests[i].startHop; j < tests[i].endHop; j++ {
					scheme := kemSchemes.ByName(tests[i].kemName)
					g := geo.KEMGeometryFromUserForwardPayloadLength(scheme, tests[i].payloadSize, false, j)
					t.Logf("Hops: %d, HeaderLength: %d, PacketLength: %d", j, g.HeaderLength, g.PacketLength)
				}
			}
		})
	}
}

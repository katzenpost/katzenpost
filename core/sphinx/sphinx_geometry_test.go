// SPDX-FileCopyrightText: Copyright (C) 2024 David Stainton
// SPDX-License-Identifier: AGPL-3.0-or-later

//go:build cartesian_product_test
// +build cartesian_product_test

package sphinx

import (
	"fmt"
	"testing"

	"github.com/schwarmco/go-cartesian-product"
	"github.com/stretchr/testify/require"

	kemScheme "github.com/katzenpost/hpqc/kem/schemes"
	nikeScheme "github.com/katzenpost/hpqc/nike/schemes"

	"github.com/katzenpost/katzenpost/core/sphinx/geo"
)

type geometryCases struct {
	name        string
	isNIKE      bool // KEM if false
	nikeName    string
	kemName     string
	nrHops      int
	payloadSize int
}

func TestSphinxGeometryCartesianProduct(t *testing.T) {
	nikeName := []interface{}{"x25519", "x448", "CTIDH512", "CTIDH1024", "CTIDH2048", "CTIDH1024-X448"}
	nrHops := []interface{}{5, 7, 10, 22}
	payloadSize := []interface{}{500, 1000, 2000, 20000, 30000, 50000}

	c1 := cartesian.Iter(nikeName, nrHops, payloadSize)

	nikeCases := []*geometryCases{}

	for product := range c1 {
		newCase := &geometryCases{
			name:        fmt.Sprintf("NIKE %s", product[0]),
			isNIKE:      true,
			nikeName:    product[0].(string),
			kemName:     "",
			nrHops:      product[1].(int),
			payloadSize: product[2].(int),
		}
		nikeCases = append(nikeCases, newCase)
	}

	kemName := []interface{}{"x25519", "x448", "CTIDH512", "CTIDH1024", "CTIDH2048", "CTIDH1024-X448", "MLKEM768", "sntrup4591761", "FrodoKEM-640-SHAKE", "Xwing", "MLKEM768-X25519", "MLKEM768-X448"}

	c2 := cartesian.Iter(kemName, nrHops, payloadSize)

	kemCases := []*geometryCases{}

	for product := range c2 {
		newCase := &geometryCases{
			name:        fmt.Sprintf("KEM %s", product[0]),
			isNIKE:      false,
			nikeName:    "",
			kemName:     product[0].(string),
			nrHops:      product[1].(int),
			payloadSize: product[2].(int),
		}
		kemCases = append(kemCases, newCase)
	}

	allCases := append(nikeCases, kemCases...)
	for i, mycase := range allCases {
		t.Logf("case #%d Name: %s nrHops: %d payloadsize: %d", i, mycase.name, mycase.nrHops, mycase.payloadSize)

		if mycase.isNIKE {
			scheme := nikeScheme.ByName(mycase.nikeName)
			require.NotNil(t, scheme)
			g := geo.GeometryFromUserForwardPayloadLength(scheme, mycase.payloadSize, true, mycase.nrHops)
			overhead := float64(g.PacketLength) / float64(g.UserForwardPayloadLength)
			t.Logf("NIKE Sphinx PacketLength: %d UserForwardPayloadLength: %d = overhead %f", g.PacketLength, g.UserForwardPayloadLength, overhead)
		} else { // KEM
			scheme := kemScheme.ByName(mycase.kemName)
			if scheme == nil {
				panic(fmt.Sprintf("failed scheme name %s", mycase.kemName))
			}
			require.NotNil(t, scheme)
			g := geo.KEMGeometryFromUserForwardPayloadLength(scheme, mycase.payloadSize, true, mycase.nrHops)
			overhead := float64(g.PacketLength) / float64(g.UserForwardPayloadLength)
			t.Logf("KEM Sphinx PacketLength: %d UserForwardPayloadLength: %d = overhead %f", g.PacketLength, g.UserForwardPayloadLength, overhead)
		}
	}

}

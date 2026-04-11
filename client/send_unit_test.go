// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package client

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/hash"

	cpki "github.com/katzenpost/katzenpost/core/pki"
)

func makeTestDoc() (*cpki.Document, *[32]byte, *[32]byte) {
	gatewayKey := []byte("gateway-identity-key-for-testing!")
	serviceKey := []byte("service-identity-key-for-testing!")

	gatewayHash := hash.Sum256(gatewayKey)
	serviceHash := hash.Sum256(serviceKey)

	doc := &cpki.Document{
		GatewayNodes: []*cpki.MixDescriptor{
			{
				Name:          "gateway1",
				IdentityKey:   gatewayKey,
				IsGatewayNode: true,
			},
		},
		ServiceNodes: []*cpki.MixDescriptor{
			{
				Name:        "service1",
				IdentityKey: serviceKey,
			},
		},
	}
	return doc, &gatewayHash, &serviceHash
}

func TestGetSourceAndDestinationNodes(t *testing.T) {
	doc, gatewayHash, serviceHash := makeTestDoc()

	t.Run("forward path", func(t *testing.T) {
		src, dst, err := getSourceAndDestinationNodes(doc, gatewayHash, serviceHash, true)
		require.NoError(t, err)
		require.Equal(t, "gateway1", src.Name)
		require.Equal(t, "service1", dst.Name)
	})

	t.Run("reverse path", func(t *testing.T) {
		src, dst, err := getSourceAndDestinationNodes(doc, gatewayHash, serviceHash, false)
		require.NoError(t, err)
		require.Equal(t, "service1", src.Name)
		require.Equal(t, "gateway1", dst.Name)
	})

	t.Run("gateway not found", func(t *testing.T) {
		wrongHash := new([32]byte)
		wrongHash[0] = 0xFF
		_, _, err := getSourceAndDestinationNodes(doc, wrongHash, serviceHash, true)
		require.Error(t, err)
		var pe *PKIError
		require.ErrorAs(t, err, &pe)
	})

	t.Run("service not found", func(t *testing.T) {
		wrongHash := new([32]byte)
		wrongHash[0] = 0xFF
		_, _, err := getSourceAndDestinationNodes(doc, gatewayHash, wrongHash, true)
		require.Error(t, err)
		var pe *PKIError
		require.ErrorAs(t, err, &pe)
	})

	t.Run("reverse gateway not found", func(t *testing.T) {
		wrongHash := new([32]byte)
		wrongHash[0] = 0xFF
		_, _, err := getSourceAndDestinationNodes(doc, wrongHash, serviceHash, false)
		require.Error(t, err)
	})

	t.Run("reverse service not found", func(t *testing.T) {
		wrongHash := new([32]byte)
		wrongHash[0] = 0xFF
		_, _, err := getSourceAndDestinationNodes(doc, gatewayHash, wrongHash, false)
		require.Error(t, err)
	})
}

// SPDX-License-Identifier: AGPL-3.0-only

package pkicache

import (
	"testing"

	signSchemes "github.com/katzenpost/hpqc/sign/schemes"
	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/pki"
)

func TestNewEmptyTopologyGatewayNoPanic(t *testing.T) {
	scheme := signSchemes.ByName("Ed25519")
	idPub, _, err := scheme.GenerateKey()
	require.NoError(t, err)

	blob, err := idPub.MarshalBinary()
	require.NoError(t, err)

	doc := &pki.Document{
		GatewayNodes: []*pki.MixDescriptor{
			{
				Name:          "gateway",
				IdentityKey:   blob,
				IsGatewayNode: true,
			},
		},
		Topology: nil,
	}

	require.NotPanics(t, func() {
		_, err = New(doc, idPub, true, false)
	}, "New must not panic when the document has an empty topology")
	require.NoError(t, err)
}

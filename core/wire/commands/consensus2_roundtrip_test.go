// SPDX-License-Identifier: AGPL-3.0-only

package commands

import (
	"testing"

	"github.com/stretchr/testify/require"

	ecdh "github.com/katzenpost/hpqc/nike/x25519"
	"github.com/katzenpost/hpqc/rand"

	"github.com/katzenpost/katzenpost/core/sphinx/geo"
)

func TestConsensus2DecodedIsReEncodable(t *testing.T) {
	t.Parallel()

	nike := ecdh.Scheme(rand.Reader)
	geo := geo.GeometryFromUserForwardPayloadLength(nike, 123, true, 5)
	cmds := NewMixnetCommands(geo)

	orig := &Consensus2{
		Cmds:       cmds,
		ErrorCode:  0,
		ChunkNum:   10,
		ChunkTotal: 20,
		Payload:    []byte("abc123"),
	}

	blob := orig.ToBytes()
	c, err := cmds.FromBytes(blob)
	require.NoError(t, err)

	decoded, ok := c.(*Consensus2)
	require.True(t, ok)

	var reencoded []byte
	require.NotPanics(t, func() { reencoded = decoded.ToBytes() },
		"re-encoding a decoded Consensus2 must not panic on a nil Cmds back-reference")
	require.Equal(t, blob, reencoded, "decoded Consensus2 must round-trip byte-for-byte")
}

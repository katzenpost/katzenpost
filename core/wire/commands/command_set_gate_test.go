// SPDX-License-Identifier: AGPL-3.0-only

package commands

import (
	"testing"

	"github.com/stretchr/testify/require"

	nikeSchemes "github.com/katzenpost/hpqc/nike/schemes"
	signSchemes "github.com/katzenpost/hpqc/sign/schemes"

	"github.com/katzenpost/katzenpost/core/sphinx"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
)

func testPKICommands(t *testing.T) *Commands {
	t.Helper()
	return NewPKICommands(signSchemes.ByName("ed25519"))
}

func testReplicaCommands(t *testing.T) *Commands {
	t.Helper()
	nike := nikeSchemes.ByName("x25519")
	g := geo.GeometryFromUserForwardPayloadLength(nike, 5000, true, 5)
	return NewStorageReplicaCommands(sphinx.NewSphinx(g).Geometry(), nike)
}

// assertRejected asserts that FromBytes rejects an id-body frame with
// errInvalidCommand and does not panic.
func assertRejected(t *testing.T, cmds *Commands, id commandID, body []byte, msg string) {
	t.Helper()
	frame := rawCommandFrame(id, body)
	var (
		cmd Command
		err error
	)
	require.NotPanics(t, func() { cmd, err = cmds.FromBytes(frame) }, msg)
	require.Nil(t, cmd, msg)
	require.ErrorIs(t, err, errInvalidCommand, msg)
}

// TestCommandSetGateRejectsCrossRole verifies that FromBytes rejects command
// ids that do not belong to the session's role before dispatching to any
// per-command deserializer. Ids that currently deserialize successfully on the
// wrong role (sendPacket on PKI, replicaDecoy on mixnet) are the clean
// red-green witnesses; the remaining cases are regression coverage for the
// cross-session nil-deref class.
func TestCommandSetGateRejectsCrossRole(t *testing.T) {
	t.Parallel()

	mixnet := testMixnetCommands(t)
	pki := testPKICommands(t)
	replica := testReplicaCommands(t)

	sphinxPacket := make([]byte, mixnet.geo.PacketLength)

	// sendPacket is a mixnet id; a PKI session must not parse it. Without the
	// gate this returns a SendPacket with nil error.
	assertRejected(t, pki, sendPacket, sphinxPacket, "sendPacket must be rejected by a PKI session")

	// replicaDecoy is a zero-length command handled in the inline switch; a
	// mixnet session must not accept it. Without the gate this returns a
	// ReplicaDecoy with nil error.
	assertRejected(t, mixnet, replicaDecoy, nil, "replicaDecoy must be rejected by a mixnet session")

	// Dirauth-only ids on a mixnet session (e.g. a gateway).
	for _, id := range []commandID{vote, getVote, reveal, certificate, sig, postDescriptor} {
		assertRejected(t, mixnet, id, make([]byte, 64), "dirauth id must be rejected by a mixnet session")
	}

	// Cross-role ids that the individual nil guards also cover.
	assertRejected(t, mixnet, replicaMessage, make([]byte, 128), "replicaMessage must be rejected by a mixnet session")
	assertRejected(t, pki, replicaMessage, make([]byte, 128), "replicaMessage must be rejected by a PKI session")
	assertRejected(t, pki, message, make([]byte, 128), "message must be rejected by a PKI session")

	// A mix/dirauth reply id on the replica session must also be rejected.
	assertRejected(t, replica, message, make([]byte, 128), "message must be rejected by a replica session")
	assertRejected(t, replica, vote, make([]byte, 64), "vote must be rejected by a replica session")
}

// TestCommandSetGateAllowsInRole verifies the gate does not over-restrict: an
// id that legitimately belongs to a role still parses.
func TestCommandSetGateAllowsInRole(t *testing.T) {
	t.Parallel()

	mixnet := testMixnetCommands(t)
	pki := testPKICommands(t)
	replica := testReplicaCommands(t)

	// noOp and disconnect are generic and valid on every role.
	for _, cmds := range []*Commands{mixnet, pki, replica} {
		cmd, err := cmds.FromBytes(rawCommandFrame(noOp, nil))
		require.NoError(t, err)
		require.IsType(t, &NoOp{}, cmd)

		cmd, err = cmds.FromBytes(rawCommandFrame(disconnect, nil))
		require.NoError(t, err)
		require.IsType(t, &Disconnect{}, cmd)
	}

	// getConsensus is a dirauth request the PKI session must accept.
	cmd, err := pki.FromBytes(rawCommandFrame(getConsensus, make([]byte, getConsensusLength)))
	require.NoError(t, err)
	require.IsType(t, &GetConsensus{}, cmd)

	// replicaDecoy is valid on a replica session.
	cmd, err = replica.FromBytes(rawCommandFrame(replicaDecoy, nil))
	require.NoError(t, err)
	require.IsType(t, &ReplicaDecoy{}, cmd)
}

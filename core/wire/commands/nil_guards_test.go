// SPDX-License-Identifier: AGPL-3.0-only

package commands

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestReplicaMessageFromBytesNilScheme exercises C3: replicaMessageFromBytes
// dereferences the NIKE scheme (HybridKeySize -> scheme.PublicKeySize) before
// any length check. On a non-replica command set the scheme is nil, so a
// replicaMessage must be rejected rather than panicking on the nil interface.
func TestReplicaMessageFromBytesNilScheme(t *testing.T) {
	t.Parallel()
	require := require.New(t)

	cmds := &Commands{} // replicaNikeScheme is nil, as on mixnet/PKI sessions.
	body := make([]byte, 128)

	var (
		cmd Command
		err error
	)
	require.NotPanics(func() { cmd, err = replicaMessageFromBytes(body, cmds) },
		"replicaMessage with a nil NIKE scheme must not panic")
	require.Nil(cmd)
	require.ErrorIs(err, errInvalidCommand)
}

// TestMessageFromBytesNilGeometry exercises C4: messageFromBytes dereferences
// the sphinx geometry for its length computation. On a PKI command set the
// geometry is nil, so a message must be rejected rather than panicking.
func TestMessageFromBytesNilGeometry(t *testing.T) {
	t.Parallel()
	require := require.New(t)

	cmds := &Commands{} // geo is nil, as on a PKI/dirauth session.
	body := make([]byte, 128)

	var (
		cmd Command
		err error
	)
	require.NotPanics(func() { cmd, err = cmds.messageFromBytes(body, cmds) },
		"message with a nil geometry must not panic")
	require.Nil(cmd)
	require.ErrorIs(err, errInvalidCommand)
}

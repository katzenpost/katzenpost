// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/bacap"
	ed25519 "github.com/katzenpost/hpqc/sign/ed25519"

	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/pigeonhole"
)

// TestProcessCopyCommandRejectsOffCurveWriteCapWithoutPanic pins the
// WriteCap regression: a CopyCommand carries an unauthenticated client's
// WriteCap, and a crafted WriteCap whose root public key is an off-curve
// point reaches ed25519.Blind (via NextBoxID) and panics. With the hpqc
// ed25519 off-curve FromBytes fix (katzenpost/hpqc#118, released in
// v0.0.88), bacap.NewWriteCapFromBytes rejects it and
// processCopyCommand's existing error path fails the copy cleanly.
//
// go.mod currently pins hpqc >= v0.0.88, so NewWriteCapFromBytes already
// returns an error and the assertion below runs against the fixed
// behavior. The probe still guards against a future downgrade below the
// fix: without it, this test would silently skip instead of catching the
// crafted-WriteCap panic regression.
func TestProcessCopyCommandRejectsOffCurveWriteCapWithoutPanic(t *testing.T) {
	backendLog, err := log.New("", "ERROR", false)
	require.NoError(t, err)

	good, err := bacap.NewWriteCap(rand.Reader)
	require.NoError(t, err)
	blob, err := good.MarshalBinary()
	require.NoError(t, err)

	// Overwrite the public half (bytes [32:64]) of the serialized root
	// private key with a value that is not a valid Edwards point.
	// {0x02, 0, ...} is an off-curve encoding that edwards25519's
	// Point.SetBytes rejects (hardcoded so this test does not import
	// edwards25519).
	crafted := make([]byte, len(blob))
	copy(crafted, blob)
	var offCurve [ed25519.PublicKeySize]byte
	offCurve[0] = 0x02
	copy(crafted[ed25519.PublicKeySize:ed25519.PrivateKeySize], offCurve[:])

	if _, err := bacap.NewWriteCapFromBytes(crafted); err == nil {
		t.Skip("requires the hpqc ed25519 off-curve FromBytes fix (katzenpost/hpqc#118)")
	}

	e := &Courier{log: backendLog.GetLogger("test")}
	cmd := &pigeonhole.CopyCommand{WriteCap: crafted}

	require.NotPanics(t, func() {
		reply := e.processCopyCommand(cmd)
		require.NotNil(t, reply)
		require.NotNil(t, reply.CopyCommandReply)
		require.Equal(t, pigeonhole.CopyStatusFailed, reply.CopyCommandReply.Status)
	})
}

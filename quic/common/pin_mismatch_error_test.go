// SPDX-License-Identifier: AGPL-3.0-only

package common

import (
	"encoding/hex"
	"testing"

	signschemes "github.com/katzenpost/hpqc/sign/schemes"
	"github.com/stretchr/testify/require"
)

func TestPinMismatchErrorNamesPresentedAndExpectedHashPrefixes(t *testing.T) {
	_, identityPrivateKey, err := signschemes.ByName(testIdentityScheme).GenerateKey()
	require.NoError(t, err)
	clock := newEpochClock(CurrentEpoch())
	keys := newTestEpochKeys(t, t.TempDir(), clock)
	l, err := ListenWithEpochKeys("127.0.0.1:0", identityPrivateKey, keys, nil)
	require.NoError(t, err)
	defer l.Close()
	presented := currentKeyHash(t, keys)
	expected := currentKeyHash(t, newTestEpochKeys(t, t.TempDir(), clock))

	err = dialPinned(t, l.Addr().String(), expected)
	require.ErrorIs(t, err, ErrQUICKeyMismatch)
	require.ErrorContains(t, err, "presented "+hex.EncodeToString(presented[:4]))
	require.ErrorContains(t, err, "expected "+hex.EncodeToString(expected[:4]))
}

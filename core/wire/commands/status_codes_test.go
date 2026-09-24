// SPDX-License-Identifier: AGPL-3.0-only

package commands

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEpochStatusCodeValuesAreStable(t *testing.T) {
	require.Equal(t, 1, VoteTooEarly)
	require.Equal(t, 2, VoteTooLate)
	require.Equal(t, 9, RevealTooEarly)
	require.Equal(t, 13, RevealTooLate)
	require.Equal(t, 15, CertTooLate)
	require.Equal(t, 19, CertTooEarly)
	require.Equal(t, 23, SigTooLate)
	require.Equal(t, 24, SigTooEarly)
}

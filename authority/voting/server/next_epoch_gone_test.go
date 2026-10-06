// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	signSchemes "github.com/katzenpost/hpqc/sign/schemes"

	"github.com/katzenpost/katzenpost/core/epochtime"
)

func documentForNextEpochAt(t *testing.T, elapsed time.Duration) error {
	savedScheme := testSignatureScheme
	testSignatureScheme = signSchemes.ByName(testSchemeName)
	t.Cleanup(func() { testSignatureScheme = savedScheme })
	st, _, _ := newSingleAuthorityState(t)

	savedEpoch := epochtime.Epoch
	epochtime.Epoch = time.Now().Add(-elapsed)
	t.Cleanup(func() { epochtime.Epoch = savedEpoch })

	now, _, _ := epochtime.Now()
	_, err := st.documentForEpoch(now + 1)
	return err
}

func TestDocumentForNextEpochIsGoneJustPastGenerationDeadline(t *testing.T) {
	generationDeadline := 7 * (epochtime.Period / 8)
	require.ErrorIs(t, documentForNextEpochAt(t, generationDeadline+time.Second), errGone)
}

func TestDocumentForNextEpochIsNotYetJustBeforeGenerationDeadline(t *testing.T) {
	generationDeadline := 7 * (epochtime.Period / 8)
	require.ErrorIs(t, documentForNextEpochAt(t, generationDeadline-time.Second), errNotYet)
}

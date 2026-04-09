// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package client2

import (
	"testing"

	"github.com/stretchr/testify/require"

	cpki "github.com/katzenpost/katzenpost/core/pki"
)

func TestRatesFromPKIDoc(t *testing.T) {
	t.Run("normal values", func(t *testing.T) {
		doc := &cpki.Document{
			LambdaP:         0.005,
			LambdaPMaxDelay: 30000,
		}
		rates := ratesFromPKIDoc(doc)
		require.Equal(t, 0.005, rates.messageOrLoop)
		require.Equal(t, uint64(30000), rates.messageOrLoopMaxDelay)
	})

	t.Run("zero values", func(t *testing.T) {
		doc := &cpki.Document{}
		rates := ratesFromPKIDoc(doc)
		require.Equal(t, float64(0), rates.messageOrLoop)
		require.Equal(t, uint64(0), rates.messageOrLoopMaxDelay)
	})

	t.Run("large values", func(t *testing.T) {
		doc := &cpki.Document{
			LambdaP:         100.5,
			LambdaPMaxDelay: ^uint64(0),
		}
		rates := ratesFromPKIDoc(doc)
		require.Equal(t, 100.5, rates.messageOrLoop)
		require.Equal(t, ^uint64(0), rates.messageOrLoopMaxDelay)
	})
}

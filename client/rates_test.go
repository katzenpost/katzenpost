// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package client

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
			LambdaL:         0.0025,
			LambdaLMaxDelay: 30000,
		}
		rates := ratesFromPKIDoc(doc)
		require.Equal(t, 0.005, rates.messageOrLoop)
		require.Equal(t, uint64(30000), rates.messageOrLoopMaxDelay)
		require.Equal(t, 0.0025, rates.loop)
		require.Equal(t, uint64(30000), rates.loopMaxDelay)
	})

	t.Run("zero values", func(t *testing.T) {
		doc := &cpki.Document{}
		rates := ratesFromPKIDoc(doc)
		require.Equal(t, float64(0), rates.messageOrLoop)
		require.Equal(t, uint64(0), rates.messageOrLoopMaxDelay)
		require.Equal(t, float64(0), rates.loop)
		require.Equal(t, uint64(0), rates.loopMaxDelay)
	})

	t.Run("large values", func(t *testing.T) {
		doc := &cpki.Document{
			LambdaP:         100.5,
			LambdaPMaxDelay: ^uint64(0),
			LambdaL:         50.25,
			LambdaLMaxDelay: ^uint64(0),
		}
		rates := ratesFromPKIDoc(doc)
		require.Equal(t, 100.5, rates.messageOrLoop)
		require.Equal(t, ^uint64(0), rates.messageOrLoopMaxDelay)
		require.Equal(t, 50.25, rates.loop)
		require.Equal(t, ^uint64(0), rates.loopMaxDelay)
	})

	t.Run("LambdaL omitted leaves loop dormant", func(t *testing.T) {
		// A consensus document that publishes only LambdaP (the
		// common docker-mixnet shape today) yields a Rates whose
		// loop rate is zero, so the sender's LambdaL ticker stays
		// dormant rather than firing at an undefined rate.
		doc := &cpki.Document{
			LambdaP:         0.001,
			LambdaPMaxDelay: 10000,
		}
		rates := ratesFromPKIDoc(doc)
		require.Equal(t, 0.001, rates.messageOrLoop)
		require.Equal(t, float64(0), rates.loop)
	})
}

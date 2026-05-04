// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package common

import (
	"math"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLambdaRateToMs(t *testing.T) {
	ms, err := LambdaRateToMs(0.00025)
	require.NoError(t, err)
	require.Equal(t, uint64(4000), ms)

	ms, err = LambdaRateToMs(0.001)
	require.NoError(t, err)
	require.Equal(t, uint64(1000), ms)

	// math.Ceil avoids silent truncation to 0 when lambda > 1.
	ms, err = LambdaRateToMs(2.0)
	require.NoError(t, err)
	require.Equal(t, uint64(1), ms)

	ms, err = LambdaRateToMs(1.5)
	require.NoError(t, err)
	require.Equal(t, uint64(1), ms)

	_, err = LambdaRateToMs(0)
	require.Error(t, err)

	_, err = LambdaRateToMs(-0.1)
	require.Error(t, err)

	_, err = LambdaRateToMs(math.NaN())
	require.Error(t, err)

	_, err = LambdaRateToMs(math.Inf(1))
	require.Error(t, err)
}

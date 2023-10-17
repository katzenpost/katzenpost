// SPDX-FileCopyrightText: © 2023 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package client2

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPoissonProcessUpdateConnectionStatus(t *testing.T) {
	lambda := 0.0005
	lambdaMaxDelay := uint64(1000)
	actions := 0
	actionCh := make(chan struct{})
	action := func() {
		actions += 1
		actionCh <- struct{}{}
	}
	p := NewPoissonProcess(lambda, lambdaMaxDelay, action)
	p.UpdateConnectionStatus(true)
	<-actionCh
	p.Halt()
	require.Equal(t, 1, actions)
}

func TestPoissonProcessUpdateRate(t *testing.T) {
	lambda := 0.0005
	lambdaMaxDelay := uint64(1000)
	actions := 0
	actionCh := make(chan struct{})
	action := func() {
		actions += 1
		actionCh <- struct{}{}
	}
	p := NewPoissonProcess(lambda, lambdaMaxDelay, action)
	lambda2 := 0.025
	p.UpdateRate(lambda2, lambdaMaxDelay)
	p.Halt()
	require.Equal(t, p.lambda, lambda2)
}

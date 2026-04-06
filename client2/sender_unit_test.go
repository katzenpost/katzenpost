// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package client2

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/log"
)

func TestSenderUpdateRatesInvalid(t *testing.T) {
	in := make(chan *Request)
	out := make(chan *Request)
	logBackend, err := log.New("", "debug", false)
	require.NoError(t, err)

	s := newSender(in, out, false, logBackend)
	defer s.Halt()

	// Zero rate should not panic, just log warning
	s.UpdateRates(&Rates{messageOrLoop: 0})

	// Negative rate should not panic
	s.UpdateRates(&Rates{messageOrLoop: -1})
}

func TestNewLoopDecoy(t *testing.T) {
	req := newLoopDecoy()
	require.NotNil(t, req)
	require.NotNil(t, req.SendLoopDecoy)
	require.Nil(t, req.SendMessage)
	require.Nil(t, req.NewKeypair)
}

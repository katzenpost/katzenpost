// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package client2

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/bacap"
)

var (
	dummyWriteCap        bacap.WriteCap
	dummyReadCap         bacap.ReadCap
	dummyMessageBoxIndex bacap.MessageBoxIndex
)

func TestReplicaError(t *testing.T) {
	err := &replicaError{code: 42}
	require.Contains(t, err.Error(), "42")
	require.Contains(t, err.Error(), "replica error code")
}

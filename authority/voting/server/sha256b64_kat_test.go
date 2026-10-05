// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSha256b64KAT(t *testing.T) {
	require.Equal(t, "JGqzSeqDkLPOTVs7Y/nvY0Jhg0NIl4O+kuu70d1v4XY=", sha256b64([]byte("katzenpost")))
}

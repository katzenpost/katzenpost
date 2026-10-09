// SPDX-License-Identifier: AGPL-3.0-only

package common

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/wire"
)

func TestConfigMatchesTheTCPLinkTimeouts(t *testing.T) {
	cfg := Config()
	require.Equal(t, wire.DefaultReadTimeout, cfg.MaxIdleTimeout, "a quiet quic link must live as long as the wire session reading it")
	require.Equal(t, 3*time.Minute, cfg.KeepAlivePeriod, "quic keepalives must follow the tcp keepalive period")
}

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
	require.Equal(t, 45*time.Second, cfg.KeepAlivePeriod, "quic keepalives must stay under half the idle timeout with their jitter")
}

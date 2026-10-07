// SPDX-License-Identifier: AGPL-3.0-only

package client

import (
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/client/config"
	"github.com/katzenpost/katzenpost/core/log"
	cpki "github.com/katzenpost/katzenpost/core/pki"
)

func clientConfigWithMaxConsensusSize(t *testing.T, size int) ([]byte, error) {
	b, err := os.ReadFile(testClientTOML)
	require.NoError(t, err)
	s := regexp.MustCompile(`(?m)^[ \t]*MaxConsensusSize = .*\n`).ReplaceAllString(string(b), "")
	require.Contains(t, s, "[VotingAuthority]\n")
	s = strings.Replace(s, "[VotingAuthority]\n", fmt.Sprintf("[VotingAuthority]\n  MaxConsensusSize = %d\n", size), 1)
	return []byte(s), nil
}

func TestClientUsesConfiguredMaxConsensusSize(t *testing.T) {
	const size = 3 * 1024 * 1024
	b, err := clientConfigWithMaxConsensusSize(t, size)
	require.NoError(t, err)
	cfg, err := config.Load(b)
	require.NoError(t, err)
	setupClientCallbacks(cfg)

	logBackend, err := log.New("", "ERROR", false)
	require.NoError(t, err)
	c, err := New(cfg, logBackend)
	require.NoError(t, err)
	require.NoError(t, c.Start())
	defer c.Shutdown()
	require.Equal(t, size, c.maxConsensusSize)
}

func TestClientRejectsNegativeMaxConsensusSize(t *testing.T) {
	b, err := clientConfigWithMaxConsensusSize(t, -1)
	require.NoError(t, err)
	_, err = config.Load(b)
	require.Error(t, err)
}

func TestClientRejectsMaxConsensusSizeAboveTheCeiling(t *testing.T) {
	b, err := clientConfigWithMaxConsensusSize(t, cpki.MaxConsensusCeiling)
	require.NoError(t, err)
	_, err = config.Load(b)
	require.NoError(t, err)
	b, err = clientConfigWithMaxConsensusSize(t, cpki.MaxConsensusCeiling+1)
	require.NoError(t, err)
	_, err = config.Load(b)
	require.Error(t, err)
}

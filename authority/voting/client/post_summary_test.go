// SPDX-License-Identifier: AGPL-3.0-only

package client

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/authority/voting/server/config"
)

func TestUpdatePostSummaryUsesAttemptKind(t *testing.T) {
	states := map[string]*postPeerState{
		"a": {peer: &config.Authority{Identifier: "a"}, lastErr: errors.New("dial Descriptor host: connection refused"), lastKind: postAttemptTransport},
		"b": {peer: &config.Authority{Identifier: "b"}, lastErr: errors.New("status 9"), lastKind: postAttemptSemantic},
	}
	s := updatePostSummary(states)
	require.Equal(t, 1, s.transportErrors)
	require.Equal(t, 1, s.semanticErrors)
	require.Len(t, s.errs, 2)
}

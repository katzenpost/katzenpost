// SPDX-License-Identifier: AGPL-3.0-only

package replica

import (
	"regexp"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/log/logtest"
)

func TestLogCallsCarryNoBoxIDs(t *testing.T) {
	require.Empty(t, logtest.ArgsMatching(t, regexp.MustCompile(`(?i)boxid`), "state.go", "handlers.go"))
}

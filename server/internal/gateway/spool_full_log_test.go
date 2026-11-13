// SPDX-License-Identifier: AGPL-3.0-only

package gateway

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/server/internal/packet"
	"github.com/katzenpost/katzenpost/server/spool"
)

func TestSpoolFullWarningIsRateLimited(t *testing.T) {
	logPath := filepath.Join(t.TempDir(), "gateway.log")
	logBackend, err := log.New(logPath, "INFO", false)
	require.NoError(t, err)
	p := &gateway{log: logBackend.GetLogger("gateway")}

	full := fmt.Errorf("%w: detail", spool.ErrFull)
	recipientFull := fmt.Errorf("%w: detail", spool.ErrRecipientFull)
	for i := uint64(0); i < 5; i++ {
		p.storeFailed(&packet.Packet{ID: i}, full, "other")
		p.storeFailed(&packet.Packet{ID: i}, recipientFull, "other")
		p.storeFailed(&packet.Packet{ID: i}, errors.New("boom"), "other")
	}
	logBackend.Close()

	b, err := os.ReadFile(logPath)
	require.NoError(t, err)
	require.Equal(t, 1, strings.Count(string(b), "Refusing to spool packet"), string(b))
	require.NotContains(t, string(b), "boom", "other store failures stay at debug level")
}

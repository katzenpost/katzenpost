// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/bacap"

	"github.com/katzenpost/katzenpost/core/log"
)

// TestWriteTombstonesToTempChannelRecoversFromPanic pins F2: the
// tombstone-cleanup goroutine that processCopyCommand spawns runs
// outside runCopyCommand's recover, so a panic in it would crash the
// whole courier. writeTombstonesToTempChannel must recover on its own.
//
// The Courier here has a nil server, so writeTombstonesToTempChannel
// reaches e.pkiDocForSharding() (after NewStatefulWriter succeeds on a
// real WriteCap) and dereferences the nil server: a real panic in the
// real function body. Without the recover, require.NotPanics fails.
func TestWriteTombstonesToTempChannelRecoversFromPanic(t *testing.T) {
	backendLog, err := log.New("", "ERROR", false)
	require.NoError(t, err)

	good, err := bacap.NewWriteCap(rand.Reader)
	require.NoError(t, err)

	e := &Courier{log: backendLog.GetLogger("test")} // nil server on purpose
	boxIDs := [][bacap.BoxIDSize]byte{{0x01}}

	require.NotPanics(t, func() {
		e.writeTombstonesToTempChannel(good, boxIDs)
	})
}

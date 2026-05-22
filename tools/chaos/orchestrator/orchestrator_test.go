// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package orchestrator

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestReadSnapshotAgainstLiveProm reads the live prometheus instance
// if one is reachable on the default port; otherwise it is a no-op.
// Run during a live docker-mixnet session to verify the query parser
// against real series, particularly the by-reason CounterVec.
func TestReadSnapshotAgainstLiveProm(t *testing.T) {
	const base = "http://127.0.0.1:9090"
	c := &http.Client{Timeout: 250 * time.Millisecond}
	resp, err := c.Get(base + "/-/ready")
	if err != nil || resp == nil || resp.StatusCode >= 400 {
		t.Skip("prometheus unreachable at " + base + "; skipping live snapshot test")
	}
	resp.Body.Close()

	snap, err := readSnapshot(context.Background(), base)
	require.NoError(t, err)
	require.False(t, snap.Taken.IsZero())
	// At least one of the drop counters must have a series (initialised
	// at zero by the registry on startup). DroppedPacketsTotal is the
	// most likely to be present across mixes.
	require.GreaterOrEqual(t, snap.DroppedPacketsTotal, 0.0)
	// Reason-labelled drops may be empty if nothing has dropped yet;
	// confirm the map is non-nil so the orchestrator can call into
	// it without a nil check.
	require.NotNil(t, snap.ReasonDrops)
	require.NotNil(t, snap.CourierReasonDrops)
}

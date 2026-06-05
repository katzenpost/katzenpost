//go:build docker_test

// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package client

import (
	"bytes"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/rand"
)

// TestSACKWriteReadRoundTrip is the minimal end-of-path check for the windowed
// SACK ARQ: Alice writes a multi-box payload with WriteStream, Bob reads it
// back with ReadStream, and the bytes must match. It deliberately uses a
// small payload (a handful of boxes) and a small fixed window so it adds only
// a few seconds to CI; coverage of the controller logic lives in the unit
// tests (sack_test.go), not here.
func TestSACKWriteReadRoundTrip(t *testing.T) {
	t.Parallel()

	alice := setupThinClient(t)
	defer alice.Close()
	bob := setupThinClient(t)
	defer bob.Close()

	aliceDoc := validatePKIDocument(t, alice)
	validatePKIDocumentForEpoch(t, bob, aliceDoc.Epoch)

	seed := make([]byte, 32)
	_, err := rand.Reader.Read(seed)
	require.NoError(t, err)

	writeCap, readCap, err := alice.NewKeypair(seed)
	require.NoError(t, err)

	// Size the payload to span a few boxes so the window (>1) is exercised.
	geo := alice.GetPigeonholeGeometry()
	maxPayload := geo.MaxPlaintextPayloadLength - 4
	const boxes = 4
	const window = 4
	payload := make([]byte, maxPayload*boxes-7) // not an exact multiple, exercise the tail
	_, err = rand.Reader.Read(payload)
	require.NoError(t, err)
	expectedBoxes := (len(payload) + maxPayload - 1) / maxPayload

	t.Logf("SACK write: %d bytes across %d boxes, window=%d", len(payload), expectedBoxes, window)
	start := time.Now()
	nextIndex, err := alice.WriteStream(writeCap, payload, window)
	require.NoError(t, err)
	require.NotNil(t, nextIndex)
	writeElapsed := time.Since(start)
	t.Logf("SACK write complete in %s: %.2f boxes/s", writeElapsed, float64(expectedBoxes)/writeElapsed.Seconds())

	// Read the payload back with the SACK read path.
	t.Logf("SACK read: %d boxes, window=%d", expectedBoxes, window)
	start = time.Now()
	got, readNext, err := bob.ReadStream(readCap, uint32(expectedBoxes), window)
	require.NoError(t, err)
	require.NotNil(t, readNext)
	readElapsed := time.Since(start)
	t.Logf("SACK read complete in %s: %.2f boxes/s", readElapsed, float64(expectedBoxes)/readElapsed.Seconds())

	require.True(t, bytes.Equal(payload, got), "round-tripped payload must match the original")
}

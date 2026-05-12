//go:build docker_test

// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package client

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/sign"

	"github.com/katzenpost/katzenpost/client/config"
	"github.com/katzenpost/katzenpost/core/cert"
	cpki "github.com/katzenpost/katzenpost/core/pki"
)

// TestGetPKIDocumentRaw exercises the thin client's GetPKIDocumentRaw
// request against a running docker mixnet. It confirms that the daemon
// preserves the gateway's original cert.Certificate-wrapped signed
// payload (signatures intact) and that the returned document matches
// the daemon's stripped view of the same epoch.
func TestGetPKIDocumentRaw(t *testing.T) {
	t.Parallel()

	client := setupThinClient(t)
	defer client.Close()

	strippedDoc := validatePKIDocument(t, client)
	epoch := strippedDoc.Epoch

	raw, gotEpoch, err := client.GetPKIDocumentRaw(epoch)
	require.NoError(t, err)
	require.Equal(t, epoch, gotEpoch)
	require.NotEmpty(t, raw, "raw signed PKI document should not be empty")

	parsed, err := cpki.ParseDocument(raw)
	require.NoError(t, err)
	require.Equal(t, epoch, parsed.Epoch)
	require.NotEmpty(t, parsed.Signatures, "raw document must retain directory authority signatures")

	// Sum256 hashes the marshalled cert.Certificate including its
	// Signatures map; clear the parsed copy's signatures so the body
	// hash matches the stripped document the daemon already exposed.
	parsedBody := *parsed
	parsedBody.Signatures = nil
	require.Equal(t, strippedDoc.Sum256(), parsedBody.Sum256(),
		"raw document body must match the stripped document body for the same epoch")

	t.Logf("GetPKIDocumentRaw returned %d-byte signed payload with %d dirauth signatures",
		len(raw), len(parsed.Signatures))

	verifyAgainstDirauths(t, raw, epoch)
}

// TestGetPKIDocumentRawCurrentEpoch exercises the zero-epoch shortcut,
// which asks the daemon for whichever epoch it currently believes to
// be live.
func TestGetPKIDocumentRawCurrentEpoch(t *testing.T) {
	t.Parallel()

	client := setupThinClient(t)
	defer client.Close()

	strippedDoc := validatePKIDocument(t, client)

	raw, gotEpoch, err := client.GetPKIDocumentRaw(0)
	require.NoError(t, err)
	require.NotEmpty(t, raw)
	require.Equal(t, strippedDoc.Epoch, gotEpoch,
		"zero-epoch request should return whichever epoch the daemon considers current")

	parsed, err := cpki.ParseDocument(raw)
	require.NoError(t, err)
	require.Equal(t, gotEpoch, parsed.Epoch)
	require.NotEmpty(t, parsed.Signatures)
}

// TestGetPKIDocumentRawUnknownEpoch confirms that asking for an epoch
// the daemon has never cached yields a graceful error rather than a
// half-formed reply.
func TestGetPKIDocumentRawUnknownEpoch(t *testing.T) {
	t.Parallel()

	client := setupThinClient(t)
	defer client.Close()

	// An epoch far in the past that the daemon will not have cached.
	const ancientEpoch uint64 = 1

	raw, gotEpoch, err := client.GetPKIDocumentRaw(ancientEpoch)
	require.Error(t, err)
	require.Nil(t, raw)
	require.Equal(t, ancientEpoch, gotEpoch,
		"daemon should echo the requested epoch on a miss")
}

// verifyAgainstDirauths checks the raw signed payload using the daemon
// config's directory authority public keys. Failing here would indicate
// the daemon mangled the payload or the signatures were stripped en
// route, both of which the new method is supposed to prevent.
func verifyAgainstDirauths(t *testing.T, raw []byte, epoch uint64) {
	t.Helper()

	cfg, err := config.LoadFile("testdata/client.toml")
	require.NoError(t, err)
	require.NotNil(t, cfg.VotingAuthority, "client config must list dirauth peers")
	require.NotEmpty(t, cfg.VotingAuthority.Peers)

	verifiers := make([]sign.PublicKey, 0, len(cfg.VotingAuthority.Peers))
	for _, peer := range cfg.VotingAuthority.Peers {
		require.NotNil(t, peer.IdentityPublicKey)
		verifiers = append(verifiers, peer.IdentityPublicKey)
	}

	threshold := len(verifiers)/2 + 1
	body, good, bad, err := cert.VerifyThreshold(verifiers, threshold, raw)
	require.NoError(t, err,
		"raw PKI document must verify against the configured dirauth threshold")
	require.NotEmpty(t, body)
	require.GreaterOrEqual(t, len(good), threshold,
		"expected at least %d good signatures, got %d (bad: %d)",
		threshold, len(good), len(bad))

	t.Logf("epoch %d signed by %d/%d directory authorities (threshold %d)",
		epoch, len(good), len(verifiers), threshold)
}

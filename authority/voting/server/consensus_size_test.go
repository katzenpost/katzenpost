// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/authority/voting/server/config"
	corepki "github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/katzenpost/katzenpost/core/wire"
)

func topoCfg(pki, wireKEM, sphinxNIKE string, nMix, nGw, nSvc, nRep, nAuth int) *config.Config {
	nodes := func(n int) []*config.Node {
		s := make([]*config.Node, n)
		for i := range s {
			s[i] = &config.Node{}
		}
		return s
	}
	reps := make([]*config.StorageReplicaNode, nRep)
	for i := range reps {
		reps[i] = &config.StorageReplicaNode{}
	}
	auths := make([]*config.Authority, nAuth)
	for i := range auths {
		auths[i] = &config.Authority{}
	}
	return &config.Config{
		Authorities:     auths,
		Mixes:           nodes(nMix),
		GatewayNodes:    nodes(nGw),
		ServiceNodes:    nodes(nSvc),
		StorageReplicas: reps,
		SphinxGeometry:  &geo.Geometry{NIKEName: sphinxNIKE},
		Server:          &config.Server{PKISignatureScheme: pki, WireKEMScheme: wireKEM},
	}
}

// namenlos topology counts: 7 mixes, 5 gateways, 4 service nodes, 4 replicas,
// 6 authorities.
func namenlosCfg(wireKEM string) *config.Config {
	return topoCfg("Ed25519 Sphincs+", wireKEM, "x25519", 7, 5, 4, 4, 6)
}

// TestEstimatedCeilingScalesWithWireKEM is the core property: a larger link-key
// primitive yields a larger ceiling with no config change. McEliece keys are
// far larger than MLKEM ones, so the McEliece network's ceiling must be higher.
func TestEstimatedCeilingScalesWithWireKEM(t *testing.T) {
	mlkem := estimatedMaxConsensusSize(topoCfg("Ed25519", "MLKEM768-X25519", "x25519", 7, 5, 4, 4, 6))
	mce := estimatedMaxConsensusSize(topoCfg("Ed25519", "mceliece348864-X25519", "x25519", 7, 5, 4, 4, 6))
	require.Greater(t, mce, mlkem, "McEliece link keys must yield a larger ceiling than MLKEM")
}

// TestEstimatedCeilingNamenlosRange checks the derived ceiling for the real
// namenlos topology is sane: above the floor, and small (not near the 500 MB
// backstop) because namenlos keys are small.
func TestEstimatedCeilingNamenlosRange(t *testing.T) {
	est := estimatedMaxConsensusSize(namenlosCfg("Xwing"))
	require.GreaterOrEqual(t, est, corepki.MinConsensusCeiling)
	require.Less(t, est, 8*1024*1024)
}

// TestEffectiveMaxMessageSizeHonorsConfig verifies the operator override wins.
func TestEffectiveMaxMessageSizeHonorsConfig(t *testing.T) {
	cfg := namenlosCfg("Xwing")
	cfg.Server.MaxConsensusSize = 4242
	require.Equal(t, 4242, effectiveMaxMessageSize(cfg))
}

// TestUnderSizedOverrideIsBelowEstimate documents the item the warning guards:
// an operator override set below the derived estimate is detectable, so the
// server can warn that consensus documents may exceed the pinned ceiling.
func TestUnderSizedOverrideIsBelowEstimate(t *testing.T) {
	cfg := namenlosCfg("Xwing")
	estimated := estimatedMaxConsensusSize(cfg)
	cfg.Server.MaxConsensusSize = estimated / 2
	require.Less(t, cfg.Server.MaxConsensusSize, estimated)
	require.Equal(t, cfg.Server.MaxConsensusSize, effectiveMaxMessageSize(cfg),
		"an explicit override wins even when it is below the estimate")
}

// TestEstimatedCeilingUnknownSchemeFallsBack ensures an unusable config does not
// panic or return zero, but falls back to the built-in default.
func TestEstimatedCeilingUnknownSchemeFallsBack(t *testing.T) {
	est := estimatedMaxConsensusSize(topoCfg("bogus-sign", "bogus-kem", "x25519", 7, 5, 4, 4, 6))
	require.Equal(t, wire.DefaultMaxPKIMessageSize, est)
}

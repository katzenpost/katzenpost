// SPDX-FileCopyrightText: © 2026 Jacob Appelbaum
// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	kemschemes "github.com/katzenpost/hpqc/kem/schemes"
	nikeschemes "github.com/katzenpost/hpqc/nike/schemes"
	signschemes "github.com/katzenpost/hpqc/sign/schemes"

	"github.com/katzenpost/katzenpost/authority/voting/server/config"
	"github.com/katzenpost/katzenpost/core/wire"
	replicaCommon "github.com/katzenpost/katzenpost/replica/common"
)

// mixKeyEpochs mirrors server/internal/constants.NumMixKeys, the number of
// per-epoch Sphinx keys a descriptor carries. That package is internal to the
// mix server and cannot be imported here; the value is a protocol constant and
// the final headroom absorbs a small drift.
const mixKeyEpochs = 3

// consensusSizeHeadroom multiplies the derived estimate to cover variable
// fields (addresses, advertised service data) and modest topology growth.
const consensusSizeHeadroom = 2

// minConsensusCeiling floors the derived ceiling so a tiny testnet still has a
// workable limit.
const minConsensusCeiling = 256 * 1024

// estimatedMaxConsensusSize returns an upper estimate of the signed consensus
// document size, derived from the configured PKI schemes and the authorized
// topology. The receive ceiling is set from this so it scales with the
// primitives actually in use: a McEliece link key needs a far higher ceiling
// than an MLKEM or CTIDH one, and changing a primitive to a larger one raises
// the ceiling automatically rather than requiring a hand-edited constant.
//
// Descriptor sizes are known from the static PKI parameters; only the key and
// signature sizes matter, not their values. Variable fields (addresses,
// advertised service data) are covered by a per-descriptor budget and the
// headroom multiplier.
func estimatedMaxConsensusSize(cfg *config.Config) int {
	signScheme := signschemes.ByName(cfg.Server.PKISignatureScheme)
	kemScheme := kemschemes.ByName(cfg.Server.WireKEMScheme)
	if signScheme == nil || kemScheme == nil {
		return wire.DefaultMaxPKIMessageSize
	}

	sphinxPub := 0
	if g := cfg.SphinxGeometry; g != nil {
		switch {
		case g.NIKEName != "":
			if s := nikeschemes.ByName(g.NIKEName); s != nil {
				sphinxPub = s.PublicKeySize()
			}
		case g.KEMName != "":
			if s := kemschemes.ByName(g.KEMName); s != nil {
				sphinxPub = s.PublicKeySize()
			}
		}
	}

	signPub := signScheme.PublicKeySize()
	signSig := signScheme.SignatureSize()
	kemPub := kemScheme.PublicKeySize()
	envPub := replicaCommon.NikeScheme.PublicKeySize()

	const perDescriptorMisc = 4096 // name, addresses, advertised service data, cbor framing
	mixDesc := signPub + kemPub + mixKeyEpochs*sphinxPub + perDescriptorMisc
	replicaDesc := signPub + kemPub + mixKeyEpochs*envPub + perDescriptorMisc

	nNodes := len(cfg.Mixes) + len(cfg.GatewayNodes) + len(cfg.ServiceNodes)
	nReplica := len(cfg.StorageReplicas)
	nAuth := len(cfg.Authorities)

	const docBase = 8192       // params, shared random, prior shared random, framing
	const certSigOverhead = 96 // per-signature key hash + cbor
	unsigned := docBase + nNodes*mixDesc + nReplica*replicaDesc
	signed := unsigned + nAuth*(signSig+certSigOverhead)

	est := signed * consensusSizeHeadroom
	if est < minConsensusCeiling {
		est = minConsensusCeiling
	}
	if est > wire.MaxMessageSize {
		est = wire.MaxMessageSize
	}
	return est
}

// effectiveMaxMessageSize returns the operator-configured ceiling if set, else
// the estimate derived from the configured PKI and topology.
func effectiveMaxMessageSize(cfg *config.Config) int {
	if cfg.Server.MaxMessageSize > 0 {
		return cfg.Server.MaxMessageSize
	}
	return estimatedMaxConsensusSize(cfg)
}

// SPDX-FileCopyrightText: © 2026 Jacob Appelbaum
// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	kemschemes "github.com/katzenpost/hpqc/kem/schemes"
	nikeschemes "github.com/katzenpost/hpqc/nike/schemes"
	signschemes "github.com/katzenpost/hpqc/sign/schemes"

	"github.com/katzenpost/katzenpost/authority/voting/server/config"
	"github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/wire"
	replicaCommon "github.com/katzenpost/katzenpost/replica/common"
)

// estimatedMaxConsensusSize derives the consensus wire ceiling from the
// configured PKI schemes and the exact authorized topology, so it scales with
// the primitives in use (a McEliece link key needs a far higher ceiling than
// an MLKEM or CTIDH one) without a hand-tuned constant.
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

	envPub := 0
	if replicaCommon.NikeScheme != nil {
		envPub = replicaCommon.NikeScheme.PublicKeySize()
	}

	return pki.EstimateConsensusSize(pki.ConsensusSizeParams{
		SignPubSize:     signScheme.PublicKeySize(),
		SignSigSize:     signScheme.SignatureSize(),
		LinkKEMPubSize:  kemScheme.PublicKeySize(),
		SphinxPubSize:   sphinxPub,
		EnvelopePubSize: envPub,
		NumNodes:        len(cfg.Mixes) + len(cfg.GatewayNodes) + len(cfg.ServiceNodes),
		NumReplicas:     len(cfg.StorageReplicas),
		NumAuthorities:  len(cfg.Authorities),
	})
}

// effectiveMaxMessageSize returns the operator-configured ceiling if set, else
// the estimate derived from the configured PKI and topology.
func effectiveMaxMessageSize(cfg *config.Config) int {
	if cfg.Server.MaxConsensusSize > 0 {
		return cfg.Server.MaxConsensusSize
	}
	return estimatedMaxConsensusSize(cfg)
}

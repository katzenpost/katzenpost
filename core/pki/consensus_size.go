// SPDX-FileCopyrightText: © 2026 Jacob Appelbaum
// SPDX-License-Identifier: AGPL-3.0-only

package pki

// Consensus-size estimation. The signed consensus document size is a function
// of the static PKI parameters (key and signature sizes) and the topology
// counts, not of any key value. Both the directory authority (which knows the
// exact topology) and the PKI-fetching client (which knows the schemes and the
// authority count, and uses a node-count allowance) derive their wire message
// ceiling from EstimateConsensusSize so it scales with the primitives in use
// rather than a hand-tuned constant.

const (
	// ConsensusMixKeyEpochs mirrors server/internal/constants.NumMixKeys, the
	// number of per-epoch Sphinx keys a descriptor carries. That package is
	// internal to the mix server; this is the same protocol constant and the
	// headroom multiplier absorbs a small drift.
	ConsensusMixKeyEpochs = 3

	// consensusSizeHeadroom multiplies the derived estimate to cover variable
	// fields (addresses, advertised service data) and modest growth.
	consensusSizeHeadroom = 2

	// MinConsensusCeiling floors the derived ceiling so a tiny testnet still
	// has a workable limit.
	MinConsensusCeiling = 256 * 1024

	// MaxConsensusCeiling is the absolute backstop; it mirrors
	// wire.MaxMessageSize (kept as a literal here to avoid a dependency on the
	// wire package).
	MaxConsensusCeiling = 500000000

	perDescriptorMisc = 4096 // name, addresses, advertised service data, cbor framing
	docBase           = 8192 // params, shared random, prior shared random, framing
	certSigOverhead   = 96   // per-signature key hash + cbor
)

// ConsensusSizeParams carries the static PKI key/signature sizes and topology
// counts needed to estimate the signed consensus size. All sizes are in bytes.
type ConsensusSizeParams struct {
	SignPubSize     int
	SignSigSize     int
	LinkKEMPubSize  int
	SphinxPubSize   int
	EnvelopePubSize int

	NumNodes       int // mixes + gateways + service nodes
	NumReplicas    int
	NumAuthorities int
}

// EstimateConsensusSize returns an upper estimate of the signed consensus
// document size for the given parameters, plus the shared-random blobs that a
// certificate carries on the peer links, with headroom applied and the result
// clamped to [MinConsensusCeiling, MaxConsensusCeiling].
func EstimateConsensusSize(p ConsensusSizeParams) int {
	mixDesc := p.SignPubSize + p.LinkKEMPubSize + ConsensusMixKeyEpochs*p.SphinxPubSize + perDescriptorMisc
	replicaDesc := p.SignPubSize + p.LinkKEMPubSize + ConsensusMixKeyEpochs*p.EnvelopePubSize + perDescriptorMisc

	unsigned := docBase + p.NumNodes*mixDesc + p.NumReplicas*replicaDesc
	signed := unsigned + p.NumAuthorities*(p.SignSigSize+certSigOverhead)

	// The same derived ceiling bounds the inter-authority peer links, which
	// carry the certificate rather than only the consensus document. A
	// certificate embeds, on top of the signed body, up to two signed
	// shared-random blobs per authority (a commit and a reveal), each a full
	// signed blob carrying a signature, per-signature overhead, and the
	// shared-random value. Omitting this term let the derived ceiling fall
	// below a real certificate on a small network, so the peer certificate
	// exchange was rejected as oversized and consensus never formed. Add the
	// certificate term so the ceiling always covers the peer certificate.
	certExtra := 2 * p.NumAuthorities * (p.SignSigSize + certSigOverhead + SharedRandomLength)
	signed += certExtra

	est := signed * consensusSizeHeadroom
	if est < MinConsensusCeiling {
		est = MinConsensusCeiling
	}
	if est > MaxConsensusCeiling {
		est = MaxConsensusCeiling
	}
	return est
}

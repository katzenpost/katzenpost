// SPDX-License-Identifier: AGPL-3.0-only

package pki

import "testing"

// TestEstimateConsensusSizeCoversCertificate checks that the derived wire
// ceiling covers a real inter-authority certificate on a small network. The
// same ceiling bounds the peer links, which carry the certificate, so a
// ceiling that only models the consensus document falls below the certificate
// and the peer exchange is rejected as oversized.
//
// The parameters model a three-authority network with three mix nodes using an
// "Ed25519 Sphincs+" identity signature (public key 96 bytes, signature 49920
// bytes) and an Xwing link key (1216 bytes). A certificate adds, on top of the
// signed consensus body, a signed shared-random commit and reveal blob per
// authority; the modeled certificate below sums those independently of the
// estimator, so dropping the certificate term from EstimateConsensusSize makes
// this test fail.
func TestEstimateConsensusSizeCoversCertificate(t *testing.T) {
	const (
		signPub  = 96
		signSig  = 49920
		linkPub  = 1216
		sphinx   = 32
		envelope = 128
		numNodes = 3
		numAuth  = 3
	)

	params := ConsensusSizeParams{
		SignPubSize:     signPub,
		SignSigSize:     signSig,
		LinkKEMPubSize:  linkPub,
		SphinxPubSize:   sphinx,
		EnvelopePubSize: envelope,
		NumNodes:        numNodes,
		NumReplicas:     0,
		NumAuthorities:  numAuth,
	}

	// Model a real certificate independently of the estimator: the signed
	// consensus body (document plus one signature per authority) plus, for each
	// authority, a signed shared-random commit and reveal blob.
	mixDesc := signPub + linkPub + ConsensusMixKeyEpochs*sphinx + perDescriptorMisc
	unsigned := docBase + numNodes*mixDesc
	signedBody := unsigned + numAuth*(signSig+certSigOverhead)
	sharedRandomBlobs := 2 * numAuth * (signSig + certSigOverhead + SharedRandomLength)
	modeledCert := signedBody + sharedRandomBlobs

	// The modeled certificate is a realistically large document; the real
	// three-authority certificate for these primitives is on the order of
	// 356 KB, well above the pre-fix ceiling of 349504 bytes.
	if modeledCert <= 356000 {
		t.Fatalf("modeled certificate %d is smaller than a real three-authority certificate", modeledCert)
	}

	est := EstimateConsensusSize(params)

	if est < modeledCert {
		t.Fatalf("derived ceiling %d does not cover the modeled certificate %d", est, modeledCert)
	}
	if est <= 357000 {
		t.Fatalf("derived ceiling %d does not exceed a real three-authority certificate (~356 KB)", est)
	}
}

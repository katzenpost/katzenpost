// SPDX-FileCopyrightText: © 2025 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package geo

import (
	"strings"
	"testing"

	"github.com/katzenpost/hpqc/nike/hybrid"

	rnspigeonhole "github.com/katzenpost/katzenpost/reticulum/pigeonhole"
	rnsgeo "github.com/katzenpost/katzenpost/reticulum/geo"
)

// TestHandComputedSizes pins the byte arithmetic for a concrete
// configuration (default-Reticulum, CTIDH1024-X25519, 128 B BACAP
// payload). If any of these numbers ever changes, the change has
// to be deliberate and explained.
//
// Stack for a 128 B BACAP write:
//
//	BACAP write inner fixed (BoxID 32 + Sig 64 + Len 4 + msg_type 1) = 101
//	+ payload                                                          128
//	+ mKEM AEAD overhead (12 nonce + 16 tag)                            28
//	------------------------------------------------------------------ ---
//	mKEM-encrypted inner                                              257
//
//	cached_courier_envelope fixed framing (cache_id 16 + 2 + 60 + 60
//	  + reply_index 1 + epoch 8 + sender_pubkey_len 2 + ct_len 4)     153
//	+ inline ephemeral pubkey (cache-prime form only)                160 / 0
//	+ mKEM ciphertext                                                 257
//	------------------------------------------------------------------ ---
//	envelope (cache-hit)                                              410
//	envelope (cache-prime)                                            570
//
//	+ Noise NK1 transport AEAD tag                                     16
//	------------------------------------------------------------------ ---
//	Noise-framed (cache-hit)                                          426
//	Noise-framed (cache-prime)                                        586
func TestHandComputedSizes(t *testing.T) {
	const N = 128
	g := NewGeometry(N, hybrid.CTIDH1024X25519, rnsgeo.Default())

	cases := []struct {
		name string
		got  int
		want int
	}{
		{"CachedCourierEnvelopeWriteHit", g.CachedCourierEnvelopeWriteHit, 410},
		{"CachedCourierEnvelopeWritePrime", g.CachedCourierEnvelopeWritePrime, 570},
		{"NoiseFramedSizeWriteHit", g.NoiseFramedSizeWriteHit, 426},
		{"NoiseFramedSizeWritePrime", g.NoiseFramedSizeWritePrime, 586},
		// Read envelopes carry only the BoxID inner; payload N doesn't
		// enter into them.
		// inner = 1 + 32 = 33; mkem = 33 + 28 = 61; envelope = 153+61 = 214
		{"CachedCourierEnvelopeReadHit", g.CachedCourierEnvelopeReadHit, 214},
		{"CachedCourierEnvelopeReadPrime", g.CachedCourierEnvelopeReadPrime, 214 + 160},
		{"NoiseFramedSizeReadHit", g.NoiseFramedSizeReadHit, 230},
	}
	for _, c := range cases {
		if c.got != c.want {
			t.Errorf("%s = %d, want %d", c.name, c.got, c.want)
		}
	}
}

// TestSizesAgreeWithTrunnel cross-validates against Package 3: the
// envelope size this geometry computes for a given payload must equal
// the byte count of an actual trunnel-encoded CachedCourierEnvelope
// carrying a ciphertext of the matching size.
func TestSizesAgreeWithTrunnel(t *testing.T) {
	cases := []struct {
		name       string
		payloadLen int
	}{
		{"empty", 0},
		{"small", 64},
		{"medium", 256},
		{"large", 1024},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			g := NewGeometry(c.payloadLen, hybrid.CTIDH1024X25519, nil)

			// mKEM-encrypted inner ciphertext for a write of N bytes:
			// 101 (write inner fixed) + N + 28 (mKEM overhead)
			ciphertextLen := 101 + c.payloadLen + 28

			// Cache-hit form: pubkey omitted (sender_pubkey_len = 0).
			envHit := makeMinimalEnvelope(0, ciphertextLen)
			wireHit, err := envHit.MarshalBinary()
			if err != nil {
				t.Fatalf("MarshalBinary (hit): %v", err)
			}
			if len(wireHit) != g.CachedCourierEnvelopeWriteHit {
				t.Errorf("payload=%d: trunnel hit wire = %d B, geometry says %d B",
					c.payloadLen, len(wireHit), g.CachedCourierEnvelopeWriteHit)
			}

			// Cache-prime form: pubkey inline (160 B for CTIDH1024-X25519).
			envPrime := makeMinimalEnvelope(160, ciphertextLen)
			wirePrime, err := envPrime.MarshalBinary()
			if err != nil {
				t.Fatalf("MarshalBinary (prime): %v", err)
			}
			if len(wirePrime) != g.CachedCourierEnvelopeWritePrime {
				t.Errorf("payload=%d: trunnel prime wire = %d B, geometry says %d B",
					c.payloadLen, len(wirePrime), g.CachedCourierEnvelopeWritePrime)
			}
		})
	}
}

// TestNewGeometryFromReticulum verifies the inverse: feeding default
// Reticulum's EncryptedMDU(Link, H2) = 415 B, the geometry should
// pick the largest payload such that the cache-hit write envelope
// (plus Noise tag) fits. An envelope at maxPayload+1 must NOT fit.
//
// fixed_cost (cache-hit write, payload 0) = 153 + 101 + 28 + 16 = 298
// maxPayload = 415 - 298 = 117
func TestNewGeometryFromReticulum(t *testing.T) {
	rns := rnsgeo.Default()
	g, err := NewGeometryFromReticulum(rns, hybrid.CTIDH1024X25519)
	if err != nil {
		t.Fatalf("NewGeometryFromReticulum: %v", err)
	}

	if got, want := g.MaxPlaintextPayloadLength, 117; got != want {
		t.Errorf("MaxPlaintextPayloadLength = %d, want %d", got, want)
	}

	// Sanity: the chosen geometry's noise-framed write hit fits in one
	// Link packet, but one byte more does not.
	budget := rns.EncryptedMDU(rnsgeo.EncryptionLink, true)
	if g.NoiseFramedSizeWriteHit > budget {
		t.Errorf("at maxPayload, NoiseFramedSizeWriteHit (%d) > budget (%d)",
			g.NoiseFramedSizeWriteHit, budget)
	}
	gBigger := NewGeometry(g.MaxPlaintextPayloadLength+1, hybrid.CTIDH1024X25519, rns)
	if gBigger.NoiseFramedSizeWriteHit <= budget {
		t.Errorf("at maxPayload+1, NoiseFramedSizeWriteHit (%d) still <= budget (%d) — should overflow",
			gBigger.NoiseFramedSizeWriteHit, budget)
	}
	if gBigger.CarrierFragmentsWriteHit < 2 {
		t.Errorf("at maxPayload+1, CarrierFragmentsWriteHit = %d, want >= 2",
			gBigger.CarrierFragmentsWriteHit)
	}
}

// TestNewGeometryFromReticulumRoundTrip: NewGeometryFromReticulum
// followed by NewGeometry with the same (payload, NIKE, rns) recovers
// the same numbers.
func TestNewGeometryFromReticulumRoundTrip(t *testing.T) {
	rns := rnsgeo.Default()
	a, err := NewGeometryFromReticulum(rns, hybrid.CTIDH1024X25519)
	if err != nil {
		t.Fatalf("NewGeometryFromReticulum: %v", err)
	}
	b := NewGeometry(a.MaxPlaintextPayloadLength, hybrid.CTIDH1024X25519, rns)
	if a.NoiseFramedSizeWriteHit != b.NoiseFramedSizeWriteHit {
		t.Errorf("round-trip mismatch on NoiseFramedSizeWriteHit: %d vs %d",
			a.NoiseFramedSizeWriteHit, b.NoiseFramedSizeWriteHit)
	}
	if a.CarrierWireWriteHit != b.CarrierWireWriteHit {
		t.Errorf("round-trip mismatch on CarrierWireWriteHit: %d vs %d",
			a.CarrierWireWriteHit, b.CarrierWireWriteHit)
	}
}

// TestNewGeometryFromReticulumTooSmall verifies the error path: if
// the Reticulum geometry is too constrained for even a zero-length
// payload, return an error.
func TestNewGeometryFromReticulumTooSmall(t *testing.T) {
	tiny := &rnsgeo.Geometry{MTU: 200, TruncatedHashLen: 16} // EncryptedMDU(Link, H2) ~= ?
	if _, err := NewGeometryFromReticulum(tiny, hybrid.CTIDH1024X25519); err == nil {
		// Compute what the budget actually is to give a useful message.
		budget := tiny.EncryptedMDU(rnsgeo.EncryptionLink, true)
		t.Errorf("expected error for tiny Reticulum (EncryptedMDU=%d), got success", budget)
	}
}

// TestValidate exercises the validator.
func TestValidate(t *testing.T) {
	if err := NewGeometry(128, hybrid.CTIDH1024X25519, nil).Validate(); err != nil {
		t.Errorf("default geometry should validate: %v", err)
	}
	bad := &Geometry{MaxPlaintextPayloadLength: -1, NIKEName: "x", SignatureSchemeName: signatureSchemeName}
	if err := bad.Validate(); err == nil {
		t.Error("expected error for negative MaxPlaintextPayloadLength")
	}
	bad = &Geometry{NIKEName: "", SignatureSchemeName: signatureSchemeName}
	if err := bad.Validate(); err == nil {
		t.Error("expected error for empty NIKEName")
	}
	bad = &Geometry{NIKEName: "x", SignatureSchemeName: "Bogus"}
	if err := bad.Validate(); err == nil {
		t.Error("expected error for wrong SignatureSchemeName")
	}
}

// TestStringContainsKeyFields checks the human-readable summary
// surfaces the load-bearing numbers.
func TestStringContainsKeyFields(t *testing.T) {
	s := NewGeometry(128, hybrid.CTIDH1024X25519, rnsgeo.Default()).String()
	for _, want := range []string{"CTIDH1024-X25519", "Ed25519", "128", "410", "426"} {
		if !strings.Contains(s, want) {
			t.Errorf("String() missing %q:\n%s", want, s)
		}
	}
}

// makeMinimalEnvelope builds a CachedCourierEnvelope for size cross-checks.
// The contents don't matter; only the marshaled byte length does.
func makeMinimalEnvelope(pubkeyLen, ciphertextLen int) *rnspigeonhole.CachedCourierEnvelope {
	env := &rnspigeonhole.CachedCourierEnvelope{
		SenderPubkeyLen: uint16(pubkeyLen),
		CiphertextLen:   uint32(ciphertextLen),
	}
	if pubkeyLen > 0 {
		env.SenderPubkey = make([]uint8, pubkeyLen)
	}
	if ciphertextLen > 0 {
		env.Ciphertext = make([]uint8, ciphertextLen)
	}
	return env
}

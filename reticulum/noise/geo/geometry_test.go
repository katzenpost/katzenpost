// SPDX-FileCopyrightText: © 2025 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package geo

import (
	"strings"
	"testing"

	"github.com/katzenpost/hpqc/nike/schemes"

	rnsgeo "github.com/katzenpost/katzenpost/reticulum/geo"
)

// TestDefaultSizes pins the byte counts for the default NIKE
// (CTIDH1024-X25519): 128 + 32 = 160 B per public key. NK1 msg1 is
// just the public key (no AEAD tag because no key is established when
// msg1 is written); NK1 msg2 is public key + 16 B AEAD tag.
func TestDefaultSizes(t *testing.T) {
	g := New()
	if got, want := g.NIKESchemeName, "CTIDH1024-X25519"; got != want {
		t.Errorf("NIKESchemeName = %q, want %q", got, want)
	}
	if got, want := g.PublicKeySize, 160; got != want {
		t.Errorf("PublicKeySize = %d, want %d", got, want)
	}
	if got, want := g.AEADTagSize, 16; got != want {
		t.Errorf("AEADTagSize = %d, want %d", got, want)
	}
	if got, want := g.HandshakeMsg1Size(), 160; got != want {
		t.Errorf("HandshakeMsg1Size = %d, want %d (just the ephemeral pubkey)", got, want)
	}
	if got, want := g.HandshakeMsg2Size(), 176; got != want {
		t.Errorf("HandshakeMsg2Size = %d, want %d (pubkey + AEAD tag)", got, want)
	}
	if got, want := g.HandshakeTotalSize(), 336; got != want {
		t.Errorf("HandshakeTotalSize = %d, want %d", got, want)
	}
	if got, want := g.TransportPerMessageOverhead(), 16; got != want {
		t.Errorf("TransportPerMessageOverhead = %d, want %d (just the AEAD tag)", got, want)
	}
}

// TestTransportCiphertextSize pins the per-message arithmetic.
func TestTransportCiphertextSize(t *testing.T) {
	g := New()
	cases := []struct{ plain, want int }{
		{0, 16},      // empty plaintext, just the tag
		{1, 17},
		{256, 272},   // typical BACAP payload
		{1024, 1040},
	}
	for _, c := range cases {
		if got := g.TransportCiphertextSize(c.plain); got != c.want {
			t.Errorf("TransportCiphertextSize(%d) = %d, want %d", c.plain, got, c.want)
		}
	}
}

// TestFitsInDefaultLinkPacket asserts that under default Reticulum
// (MTU 500, no IFAC, 16 B truncated hashes, EncryptedMDU(Link,H2) = 415)
// both NK1 handshake messages fit in a single Link-encrypted packet.
// CTIDH512-X25519 NK1: msg1 = 96 B, msg2 = 112 B; both ≤ 415.
func TestFitsInDefaultLinkPacket(t *testing.T) {
	g := New()
	rns := rnsgeo.Default()
	msg1Fits, msg2Fits := g.FitsInLinkPacket(rns, true)
	if !msg1Fits {
		t.Errorf("msg1 (%d B) does not fit in EncryptedMDU(Link, H2)=%d B",
			g.HandshakeMsg1Size(),
			rns.EncryptedMDU(rnsgeo.EncryptionLink, true))
	}
	if !msg2Fits {
		t.Errorf("msg2 (%d B) does not fit in EncryptedMDU(Link, H2)=%d B",
			g.HandshakeMsg2Size(),
			rns.EncryptedMDU(rnsgeo.EncryptionLink, true))
	}
	frag1, frag2 := g.HandshakeFragmentsNeeded(rns, true)
	if frag1 != 1 {
		t.Errorf("msg1 fragments = %d, want 1", frag1)
	}
	if frag2 != 1 {
		t.Errorf("msg2 fragments = %d, want 1", frag2)
	}
}

// TestFitsAndFragmentsAgree is a property test: across registered
// hpqc NIKE schemes and several Reticulum geometries, FitsInLinkPacket
// returns true for a message iff HandshakeFragmentsNeeded returns 1
// for that message. (The two functions answer the same question via
// different routes; they had better agree.)
func TestFitsAndFragmentsAgree(t *testing.T) {
	rnsConfigs := []*rnsgeo.Geometry{
		rnsgeo.Default(),
		rnsgeo.LoRaNamedNetwork(),
		rnsgeo.LoRaAuthenticated(),
		{MTU: 250, TruncatedHashLen: 16},  // small radio
		{MTU: 1500, TruncatedHashLen: 16}, // ethernet-class
	}
	nikeNames := []string{
		"x25519",
		"x448",
		"CTIDH512-X25519",
		"CTIDH1024-X448",
	}
	for _, rns := range rnsConfigs {
		if err := rns.Validate(); err != nil {
			continue
		}
		for _, name := range nikeNames {
			scheme := schemes.ByName(name)
			if scheme == nil {
				t.Logf("skipping unregistered NIKE %q", name)
				continue
			}
			g := NewWithScheme(scheme)
			msg1Fits, msg2Fits := g.FitsInLinkPacket(rns, true)
			frag1, frag2 := g.HandshakeFragmentsNeeded(rns, true)
			if msg1Fits != (frag1 == 1) {
				t.Errorf("nike=%s mtu=%d: msg1 fits=%v but fragments=%d", name, rns.MTU, msg1Fits, frag1)
			}
			if msg2Fits != (frag2 == 1) {
				t.Errorf("nike=%s mtu=%d: msg2 fits=%v but fragments=%d", name, rns.MTU, msg2Fits, frag2)
			}
		}
	}
}

// TestNewWithScheme exercises the alternate-NIKE path with a couple
// of registered schemes.
func TestNewWithScheme(t *testing.T) {
	cases := []struct {
		name     string
		wantPubK int
	}{
		{"x25519", 32},
		{"x448", 56},
		{"CTIDH512-X25519", 96},
	}
	for _, c := range cases {
		scheme := schemes.ByName(c.name)
		if scheme == nil {
			t.Logf("NIKE %q not registered, skipping", c.name)
			continue
		}
		g := NewWithScheme(scheme)
		if g.PublicKeySize != c.wantPubK {
			t.Errorf("%s: PublicKeySize = %d, want %d", c.name, g.PublicKeySize, c.wantPubK)
		}
		if g.NIKESchemeName != scheme.Name() {
			t.Errorf("%s: NIKESchemeName = %q, want %q", c.name, g.NIKESchemeName, scheme.Name())
		}
	}
}

// TestValidate exercises the validation rules.
func TestValidate(t *testing.T) {
	if err := New().Validate(); err != nil {
		t.Errorf("default geometry should validate: %v", err)
	}
	bad := []Geometry{
		{NIKESchemeName: "x", PublicKeySize: 0, AEADTagSize: 16},
		{NIKESchemeName: "x", PublicKeySize: 96, AEADTagSize: 0},
		{NIKESchemeName: "x", PublicKeySize: 96, AEADTagSize: 16, NoiseFramingOverhead: -1},
		{NIKESchemeName: "", PublicKeySize: 96, AEADTagSize: 16},
	}
	for i, g := range bad {
		if err := g.Validate(); err == nil {
			t.Errorf("case %d: expected validation error, got nil", i)
		}
	}
}

// TestStringContainsKeyFields checks that the human-readable summary
// surfaces the load-bearing numbers.
func TestStringContainsKeyFields(t *testing.T) {
	s := New().String()
	for _, want := range []string{"CTIDH1024-X25519", "160", "16", "336"} {
		if !strings.Contains(s, want) {
			t.Errorf("String() missing %q:\n%s", want, s)
		}
	}
}

package geo

import "testing"

// TestSpecValues cross-checks the model against the six control-packet
// sizes quoted in the RNS "Wire Format" specification.
func TestSpecValues(t *testing.T) {
	g := Default()
	cases := []struct {
		name     string
		got      int
		expected int
	}{
		{"Path Request", g.PathRequestSize(), 51},
		{"Announce", g.AnnounceSize(0), 167},
		{"Link Request", g.LinkRequestSize(), 83},
		{"Link Proof", g.LinkProofSize(), 115},
		{"Link RTT", g.LinkRTTSize(), 99},
		{"Link Keepalive", g.LinkKeepaliveSize(), 20},
	}
	for _, c := range cases {
		if c.got != c.expected {
			t.Errorf("%s: got %d, want %d", c.name, c.got, c.expected)
		}
	}
}

// TestEncryptedMDU verifies the published MDU constant for default config.
func TestEncryptedMDU(t *testing.T) {
	g := Default()
	if got := g.EncryptedMDU(EncryptionSingle, true); got != 383 {
		t.Errorf("default ENCRYPTED_MDU (SINGLE, HEADER_2) = %d, want 383", got)
	}
}

// TestValidate sanity-checks the validator.
func TestValidate(t *testing.T) {
	if err := Default().Validate(); err != nil {
		t.Errorf("default geometry should validate: %v", err)
	}

	bad := New()
	bad.IFACEnabled = true
	bad.IFACLen = 0
	if err := bad.Validate(); err == nil {
		t.Error("expected error for IFAC enabled with zero length")
	}

	bad = New()
	bad.TruncatedHashLen = 24
	if err := bad.Validate(); err == nil {
		t.Error("expected error for truncated_hash_len = 24")
	}
}

// TestFragmentsAndWire spot-checks the segmentation math: for a payload
// that is exactly N * encrypted_mdu, FragmentsNeeded should return N and
// TotalWireBytes should equal N * fragmentWireBytes(per). Note that
// fragmentWireBytes(per) is MTU-1, not MTU, because EncryptedMDU
// reserves 1 byte for the mandatory PKCS7 pad.
func TestFragmentsAndWire(t *testing.T) {
	g := Default()
	per := g.EncryptedMDU(EncryptionLink, true)
	want1 := g.fragmentWireBytes(per, EncryptionLink, true)
	if want1 != g.MTU-1 {
		t.Errorf("max-plaintext fragment should be MTU-1=%d, got %d", g.MTU-1, want1)
	}
	for n := 1; n <= 5; n++ {
		payload := n * per
		if got := g.FragmentsNeeded(payload, EncryptionLink, true); got != n {
			t.Errorf("FragmentsNeeded(%d) = %d, want %d", payload, got, n)
		}
		if got := g.TotalWireBytes(payload, EncryptionLink, true); got != n*want1 {
			t.Errorf("TotalWireBytes(%d) = %d, want %d", payload, got, n*want1)
		}
	}
}

// TestPathBottleneck checks that EffectiveBodyMTU == min(MTU - IFAC).
func TestPathBottleneck(t *testing.T) {
	p := NewPath(
		Hop{Name: "ethernet", InterfaceMTU: 1500},
		Hop{Name: "lora-iface", InterfaceMTU: 500, IFACEnabled: true, IFACLen: 8},
		Hop{Name: "tcp", InterfaceMTU: 1064},
	)
	want := 500 - 8
	if got := p.EffectiveBodyMTU(); got != want {
		t.Errorf("EffectiveBodyMTU = %d, want %d", got, want)
	}
	g := p.LinkGeometry()
	if g.MTU != want || g.IFACEnabled {
		t.Errorf("LinkGeometry MTU=%d ifac=%v, want %d / disabled", g.MTU, g.IFACEnabled, want)
	}
}

// TestPathBaselineUnaffected confirms that non-Link traffic geometry
// always uses the 500-byte universal baseline, not the discovered link
// MTU, even when interfaces support larger packets.
func TestPathBaselineUnaffected(t *testing.T) {
	p := NewPath(
		Hop{InterfaceMTU: 4096},
		Hop{InterfaceMTU: 4096},
	)
	if p.BaselineGeometry().MTU != DefaultMTU {
		t.Errorf("BaselineGeometry MTU = %d, want %d", p.BaselineGeometry().MTU, DefaultMTU)
	}
}

// TestPathPerHopAndTotal checks per-hop accounting and the sum.
func TestPathPerHopAndTotal(t *testing.T) {
	p := NewPath(
		Hop{InterfaceMTU: 500},
		Hop{InterfaceMTU: 500, IFACEnabled: true, IFACLen: 16},
		Hop{InterfaceMTU: 500},
	)
	payload := 100
	g := p.LinkGeometry()
	body := g.TotalWireBytes(payload, EncryptionSingle, true)
	n := g.FragmentsNeeded(payload, EncryptionSingle, true)
	if n != 1 {
		t.Fatalf("expected 1 fragment for 100B payload, got %d", n)
	}

	per := p.HopWireBytes(payload, EncryptionSingle, true)
	want := []int{body, body + 16, body}
	for i, w := range want {
		if per[i] != w {
			t.Errorf("hop %d wire = %d, want %d", i, per[i], w)
		}
	}
	if total := p.TotalCarrierBytes(payload, EncryptionSingle, true); total != 3*body+16 {
		t.Errorf("TotalCarrierBytes = %d, want %d", total, 3*body+16)
	}
}

// TestLinkSetupAndBreakeven verifies the documented headline numbers:
// 297-byte setup and 10-packet breakeven for the default geometry.
func TestLinkSetupAndBreakeven(t *testing.T) {
	g := Default()
	if got := g.LinkSetupBytes(); got != 297 {
		t.Errorf("LinkSetupBytes = %d, want 297", got)
	}
	if got := g.BreakevenPackets(); got != 10 {
		t.Errorf("BreakevenPackets = %d, want 10", got)
	}
}

// TestLinkSetupCarrierBytes checks that setup packets accumulate
// per-hop IFAC overhead correctly.
func TestLinkSetupCarrierBytes(t *testing.T) {
	// 1-hop direct link, no IFAC: just 297 bytes.
	p1 := NewPath(Hop{InterfaceMTU: 500})
	if got := p1.LinkSetupCarrierBytes(); got != 297 {
		t.Errorf("1-hop no-IFAC setup = %d, want 297", got)
	}

	// 3 hops, middle hop has 16-byte IFAC.
	// Setup cost = 3 * 297 + 3 * 16 = 891 + 48 = 939.
	p3 := NewPath(
		Hop{InterfaceMTU: 500},
		Hop{InterfaceMTU: 500, IFACEnabled: true, IFACLen: 16},
		Hop{InterfaceMTU: 500},
	)
	want := 3*297 + 3*16
	if got := p3.LinkSetupCarrierBytes(); got != want {
		t.Errorf("3-hop setup = %d, want %d", got, want)
	}
}

// TestQueryWireCost verifies that a round-trip Query sums request and
// response symmetrically, and that the per-hop slice equals the sum of
// the per-direction per-hop counts.
func TestQueryWireCost(t *testing.T) {
	p := NewPath(
		Hop{InterfaceMTU: 500},
		Hop{InterfaceMTU: 500, IFACEnabled: true, IFACLen: 8},
	)
	q := Query{RequestBytes: 200, ResponseBytes: 1024}

	cost := q.WireCost(p, EncryptionLink)

	wantReq := p.TotalCarrierBytes(q.RequestBytes, EncryptionLink, true)
	wantRes := p.TotalCarrierBytes(q.ResponseBytes, EncryptionLink, true)
	if cost.RequestWireBytes != wantReq {
		t.Errorf("RequestWireBytes = %d, want %d", cost.RequestWireBytes, wantReq)
	}
	if cost.ResponseWireBytes != wantRes {
		t.Errorf("ResponseWireBytes = %d, want %d", cost.ResponseWireBytes, wantRes)
	}
	if cost.TotalWireBytes != wantReq+wantRes {
		t.Errorf("TotalWireBytes = %d, want %d", cost.TotalWireBytes, wantReq+wantRes)
	}
	if len(cost.PerHopWireBytes) != len(p.Hops) {
		t.Fatalf("PerHopWireBytes len = %d, want %d", len(cost.PerHopWireBytes), len(p.Hops))
	}

	reqHop := p.HopWireBytes(q.RequestBytes, EncryptionLink, true)
	resHop := p.HopWireBytes(q.ResponseBytes, EncryptionLink, true)
	for i := range p.Hops {
		if want := reqHop[i] + resHop[i]; cost.PerHopWireBytes[i] != want {
			t.Errorf("hop %d = %d, want %d", i, cost.PerHopWireBytes[i], want)
		}
	}
}

// TestBreakevenQueries confirms the breakeven calc against a hand
// computation, and that it correctly returns 0 / -1 for the edge cases.
func TestBreakevenQueries(t *testing.T) {
	p := NewPath(Hop{InterfaceMTU: 500})

	// Tiny single-fragment query: SINGLE saves only the 32-byte eph
	// pubkey per direction = 64 bytes per round trip. Setup is 297.
	// Breakeven = ceil(297 / 64) = 5 queries.
	tiny := Query{RequestBytes: 100, ResponseBytes: 100}
	if got := tiny.BreakevenQueries(p); got != 5 {
		t.Errorf("tiny query breakeven = %d, want 5", got)
	}

	// Large query that fragments many times — each fragment saves 32
	// bytes, so a multi-fragment query crosses breakeven much faster.
	big := Query{RequestBytes: 8 * 1024, ResponseBytes: 8 * 1024}
	bigBE := big.BreakevenQueries(p)
	if bigBE < 1 || bigBE >= 5 {
		t.Errorf("big query breakeven = %d, want a positive value < 5", bigBE)
	}

	// Empty round trip: no per-query saving, breakeven = -1.
	empty := Query{RequestBytes: 0, ResponseBytes: 0}
	if got := empty.BreakevenQueries(p); got != -1 {
		t.Errorf("empty query breakeven = %d, want -1", got)
	}
}

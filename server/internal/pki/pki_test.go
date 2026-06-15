// pki_test.go - Katzenpost server PKI tests.
// Copyright (C) 2026  The Katzenpost Authors.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.

package pki

import (
	"testing"

	"github.com/katzenpost/katzenpost/core/epochtime"
	cpki "github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/server/internal/pkicache"
)

// TestHasUsableDocument verifies the admission predicate the incoming listener
// relies on: a gateway with no document at all refuses connections (the boot
// case), but a gateway holding the previous epoch's document accepts them, so a
// client may still be served during the window after an epoch rollover but
// before the new consensus has been fetched.
func TestHasUsableDocument(t *testing.T) {
	now, _, _ := epochtime.Now()

	p := &pki{docs: make(map[uint64]*pkicache.Entry)}

	if p.HasUsableDocument() {
		t.Fatal("no cached document: expected not usable (boot case)")
	}

	p.docs[now-1] = &pkicache.Entry{}
	if !p.HasUsableDocument() {
		t.Fatal("previous-epoch document cached: expected usable")
	}

	delete(p.docs, now-1)
	p.docs[now] = &pkicache.Entry{}
	if !p.HasUsableDocument() {
		t.Fatal("current-epoch document cached: expected usable")
	}
}

func TestMakeDescAddrMapBracketsIPv6(t *testing.T) {
	m, err := makeDescAddrMap([]string{"tcp://[2a02:898:246:64::34:78]:4242"})
	if err != nil {
		t.Fatalf("makeDescAddrMap failed: %v", err)
	}

	got := m[cpki.TransportTCPv6]
	want := []string{"tcp://[2a02:898:246:64::34:78]:4242"}

	if len(got) != len(want) {
		t.Fatalf("unexpected tcp6 address count: got %d want %d: %#v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("unexpected tcp6 address at index %d: got %q want %q", i, got[i], want[i])
		}
	}
}

func TestMakeDescAddrMapKeepsIPv4(t *testing.T) {
	m, err := makeDescAddrMap([]string{"tcp://91.208.34.78:4242"})
	if err != nil {
		t.Fatalf("makeDescAddrMap failed: %v", err)
	}

	got := m[cpki.TransportTCPv4]
	want := []string{"tcp://91.208.34.78:4242"}

	if len(got) != len(want) {
		t.Fatalf("unexpected tcp4 address count: got %d want %d: %#v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("unexpected tcp4 address at index %d: got %q want %q", i, got[i], want[i])
		}
	}
}

func TestMakeDescAddrMapRejectsInvalidAddress(t *testing.T) {
	_, err := makeDescAddrMap([]string{"://not-a-url"})
	if err == nil {
		t.Fatal("makeDescAddrMap unexpectedly accepted an invalid URL")
	}
}

// TestDeriveBucketParams exercises the gateway-side token-bucket
// derivation that consumes doc.LambdaP and doc.LambdaL from each new
// consensus document. The headroom factor (1.1) and bucket cap (256)
// are baked-in source constants; the test pins both, so any future
// edit to either constant is forced through a deliberate test change
// rather than slipping in unnoticed.
func TestDeriveBucketParams(t *testing.T) {
	t.Parallel()

	type want struct {
		incrNs    uint64
		maxTokens uint64
	}
	cases := []struct {
		name             string
		lambdaP, lambdaL float64
		want             want
	}{
		{
			// Both rates absent: the consensus document has no
			// positive client emission rate to enforce, so the
			// gateway turns the limiter off entirely.
			name: "both zero disables limiter",
			want: want{incrNs: 0, maxTokens: 0},
		},
		{
			// LambdaL omitted (the historical docker-mixnet shape
			// before the two-ticker restoration): refill keys off
			// LambdaP alone, with the standard 10% headroom.
			// lambdaTotal = 0.001 events/ms
			// refillRate  = 0.0011 events/ms
			// incrNs      = ceil(1e6 / 0.0011) = 909_090_910 ns
			name:    "LambdaP only",
			lambdaP: 0.001,
			want:    want{incrNs: 909090910, maxTokens: 256},
		},
		{
			// Namenlos production parameters as of the migration
			// window: LambdaP=0.001, LambdaL=0.0005.
			// lambdaTotal = 0.0015 events/ms
			// refillRate  = 0.00165 events/ms
			// incrNs      = ceil(1e6 / 0.00165) = 606_060_607 ns
			//             ≈ 606 ms per token, matching the mean
			//             inter-event of 1/lambdaTotal ≈ 667 ms
			//             scaled by 1/headroom = 1/1.1.
			name:    "namenlos LambdaP+LambdaL",
			lambdaP: 0.001,
			lambdaL: 0.0005,
			want:    want{incrNs: 606060607, maxTokens: 256},
		},
		{
			// High-rate stress: at a combined rate of 1 event/ms
			// (1000/sec per client) the refill interval drops
			// below one millisecond. The math still works in
			// nanoseconds without truncation to zero, which is
			// exactly why deriveBucketParams stores the increment
			// as ns rather than ms.
			// lambdaTotal = 1.0 events/ms
			// refillRate  = 1.1 events/ms
			// incrNs      = ceil(1e6 / 1.1) = 909_091 ns (~909 µs)
			name:    "sub-millisecond refill",
			lambdaP: 0.5,
			lambdaL: 0.5,
			want:    want{incrNs: 909091, maxTokens: 256},
		},
		{
			// Negative inputs should never appear in a consensus
			// document, but a malformed document should not
			// produce a nonsensical refill rate. Treat as
			// "disabled".
			name:    "negative inputs treated as disabled",
			lambdaP: -1.0,
			lambdaL: -0.5,
			want:    want{incrNs: 0, maxTokens: 0},
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			incrNs, maxTokens := deriveBucketParams(tc.lambdaP, tc.lambdaL)
			if incrNs != tc.want.incrNs {
				t.Errorf("incrNs: got %d, want %d", incrNs, tc.want.incrNs)
			}
			if maxTokens != tc.want.maxTokens {
				t.Errorf("maxTokens: got %d, want %d", maxTokens, tc.want.maxTokens)
			}
		})
	}
}

// TestDeriveBucketParamsHeadroom confirms the long-run utilisation
// ratio rho = lambda / refillRate lands at the documented 1/1.1 for
// every positive-rate case. Stated as code so that a refactor to the
// headroom factor cannot silently invert the relationship.
func TestDeriveBucketParamsHeadroom(t *testing.T) {
	t.Parallel()

	const wantRho = 1.0 / bucketHeadroomFactor
	for _, lt := range []struct {
		lambdaP, lambdaL float64
	}{
		{0.001, 0.0005},
		{0.001, 0},
		{0.5, 0.5},
		{0.00025, 0.00025},
	} {
		incrNs, _ := deriveBucketParams(lt.lambdaP, lt.lambdaL)
		if incrNs == 0 {
			t.Fatalf("expected positive incrNs for lambdaP=%v lambdaL=%v", lt.lambdaP, lt.lambdaL)
		}
		// refillRate in events/ms = 1e6 / incrNs, so
		// rho = lambdaTotal / refillRate = lambdaTotal * incrNs / 1e6.
		lambdaTotal := lt.lambdaP + lt.lambdaL
		gotRho := lambdaTotal * float64(incrNs) / 1e6
		// The ceil in deriveBucketParams biases incrNs up by at
		// most one nanosecond, which raises rho by at most
		// lambdaTotal/1e6: that bias is below 1e-9 for every
		// realistic rate and well below any tolerance we care
		// about. A 1e-6 epsilon is comfortable.
		if diff := gotRho - wantRho; diff < -1e-6 || diff > 1e-6 {
			t.Errorf("rho for lambdaP=%v lambdaL=%v: got %v, want %v (diff %v)",
				lt.lambdaP, lt.lambdaL, gotRho, wantRho, diff)
		}
	}
}

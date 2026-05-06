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

	cpki "github.com/katzenpost/katzenpost/core/pki"
)

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

// wire_handler_test.go - Katzenpost voting authority wire handler tests.
// Copyright (C) 2026  The Katzenpost Authors.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.

package server

import (
	"strings"
	"testing"

	"github.com/katzenpost/hpqc/kem/schemes"
	ecdh "github.com/katzenpost/hpqc/nike/x25519"
	"github.com/katzenpost/hpqc/rand"
	signSchemes "github.com/katzenpost/hpqc/sign/schemes"

	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/pki"
)

const testNumMixKeys = 3

func testDescriptorKeys(t *testing.T, epoch uint64) ([]byte, []byte, map[uint64][]byte) {
	t.Helper()

	signScheme := signSchemes.ByName("Ed25519")
	if signScheme == nil {
		t.Fatal("Ed25519 signature scheme not found")
	}
	identityPublicKey, _, err := signScheme.GenerateKey()
	if err != nil {
		t.Fatalf("failed to generate identity key: %v", err)
	}
	identityKeyBlob, err := identityPublicKey.MarshalBinary()
	if err != nil {
		t.Fatalf("failed to marshal identity public key: %v", err)
	}

	linkScheme := schemes.ByName("xwing")
	if linkScheme == nil {
		t.Fatal("xwing KEM scheme not found")
	}
	linkPublicKey, _, err := linkScheme.GenerateKeyPair()
	if err != nil {
		t.Fatalf("failed to generate link key: %v", err)
	}
	linkKeyBlob, err := linkPublicKey.MarshalBinary()
	if err != nil {
		t.Fatalf("failed to marshal link public key: %v", err)
	}

	mixKeys := make(map[uint64][]byte)
	for i := epoch; i < epoch+testNumMixKeys; i++ {
		mixPubKey, _, err := ecdh.Scheme(rand.Reader).GenerateKeyPairFromEntropy(rand.Reader)
		if err != nil {
			t.Fatalf("failed to generate mix key for epoch %d: %v", i, err)
		}
		mixKeyBlob, err := mixPubKey.MarshalBinary()
		if err != nil {
			t.Fatalf("failed to marshal mix key for epoch %d: %v", i, err)
		}
		mixKeys[i] = mixKeyBlob
	}

	return identityKeyBlob, linkKeyBlob, mixKeys
}

func TestMalformedUploadedMixDescriptorAddressIsRejectedByValidation(t *testing.T) {
	epoch, _, _ := epochtime.Now()
	identityKeyBlob, linkKeyBlob, mixKeys := testDescriptorKeys(t, epoch)

	desc := &pki.MixDescriptor{
		Name:        "mixy",
		IdentityKey: identityKeyBlob,
		LinkKey:     linkKeyBlob,
		Addresses: map[string][]string{
			pki.TransportTCPv6: {"tcp://2a02:898:246:64::34:78:4242"},
		},
		MixKeys: mixKeys,
		Epoch:   epoch,
	}

	err := pki.IsDescriptorWellFormed(desc, epoch)
	if err == nil {
		t.Fatal("malformed unbracketed IPv6 descriptor was unexpectedly accepted")
	}
	if !strings.Contains(err.Error(), "invalid descriptor address") {
		t.Fatalf("unexpected validation error: %v", err)
	}
}

func TestWellFormedUploadedMixDescriptorAddressIsAcceptedByValidation(t *testing.T) {
	epoch, _, _ := epochtime.Now()
	identityKeyBlob, linkKeyBlob, mixKeys := testDescriptorKeys(t, epoch)

	desc := &pki.MixDescriptor{
		Name:        "mixy",
		IdentityKey: identityKeyBlob,
		LinkKey:     linkKeyBlob,
		Addresses: map[string][]string{
			pki.TransportTCPv6: {"tcp://[2a02:898:246:64::34:78]:4242"},
		},
		MixKeys: mixKeys,
		Epoch:   epoch,
	}

	if err := pki.IsDescriptorWellFormed(desc, epoch); err != nil {
		t.Fatalf("well-formed bracketed IPv6 descriptor was rejected: %v", err)
	}
}

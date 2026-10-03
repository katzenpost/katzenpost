// SPDX-License-Identifier: AGPL-3.0-only

package pki

import (
	"errors"
	"testing"

	"github.com/fxamacker/cbor/v2"

	"github.com/katzenpost/hpqc/kem/schemes"
	"github.com/katzenpost/hpqc/sign"
	signSchemes "github.com/katzenpost/hpqc/sign/schemes"

	"github.com/katzenpost/katzenpost/core/cert"
	"github.com/katzenpost/katzenpost/core/epochtime"
)

func TestDocumentSignatureRejection(t *testing.T) {
	ed25519 := signSchemes.ByName("Ed25519")
	authPub, authPriv, err := ed25519.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	untrustedPub, untrustedPriv, err := ed25519.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	doc := signatureTestDocument(t, ed25519.Name())

	t.Run("no signatures", func(t *testing.T) {
		raw, err := doc.MarshalCertificate()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ParseDocument(raw); !errors.Is(err, ErrDocumentNotSigned) {
			t.Fatalf("expected ErrDocumentNotSigned, got: %v", err)
		}
		if _, err := FromPayload(authPub, raw); err == nil {
			t.Fatal("expected FromPayload to reject an unsigned document")
		}
	})

	t.Run("signed by untrusted key", func(t *testing.T) {
		signed, err := SignDocument(untrustedPriv, untrustedPub, doc)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := FromPayload(authPub, signed); !errors.Is(err, cert.ErrIdentitySignatureNotFound) {
			t.Fatalf("expected ErrIdentitySignatureNotFound, got: %v", err)
		}
		_, _, _, err = cert.VerifyThreshold([]sign.PublicKey{authPub}, 1, signed)
		if !errors.Is(err, cert.ErrThresholdNotMet) {
			t.Fatalf("expected ErrThresholdNotMet, got: %v", err)
		}
	})

	t.Run("corrupted signature", func(t *testing.T) {
		signed, err := SignDocument(authPriv, authPub, doc)
		if err != nil {
			t.Fatal(err)
		}
		c := new(cert.Certificate)
		if err := cbor.Unmarshal(signed, c); err != nil {
			t.Fatal(err)
		}
		for k, sig := range c.Signatures {
			sig.Payload[0] ^= 0xff
			c.Signatures[k] = sig
		}
		tampered, err := c.Marshal()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := FromPayload(authPub, tampered); !errors.Is(err, cert.ErrBadSignature) {
			t.Fatalf("expected ErrBadSignature, got: %v", err)
		}
		_, _, _, err = cert.VerifyThreshold([]sign.PublicKey{authPub}, 1, tampered)
		if !errors.Is(err, cert.ErrThresholdNotMet) {
			t.Fatalf("expected ErrThresholdNotMet, got: %v", err)
		}
	})
}

func signatureTestDocument(t *testing.T, signatureScheme string) *Document {
	idPub, _, err := signSchemes.ByName(signatureScheme).GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	idBlob, err := idPub.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	linkKey, _, err := schemes.ByName("xwing").GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	linkBlob, err := linkKey.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	epoch, _, _ := epochtime.Now()
	doc := &Document{
		Epoch:              epoch,
		Topology:           make([][]*MixDescriptor, 3),
		Version:            DocumentVersion,
		PKISignatureScheme: signatureScheme,
	}
	doc.Topology[0] = []*MixDescriptor{{
		Name:        "node",
		IdentityKey: idBlob,
		LinkKey:     linkBlob,
		Epoch:       epoch,
		Version:     DescriptorVersion,
	}}
	return doc
}

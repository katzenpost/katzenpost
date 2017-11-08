// descriptor.go - Katzenpost Non-voting authority descriptor s11n.
// Copyright (C) 2017  Yawning Angel.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

// Package s11n implements serialization routines for the various PKI
// data structures.
package s11n

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/katzenpost/core/crypto/eddsa"
	"github.com/katzenpost/core/pki"
	"github.com/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/core/utils"
	"gopkg.in/square/go-jose.v2"
)

const nodeDescriptorVersion = "nonvoting-v0"

type nodeDescriptor struct {
	// Version uniquely identifies the descriptor format as being for the
	// non-voting authority so that it can be rejected when unexpectedly
	// posted to, or received from an authority, or if the version changes.
	Version string

	pki.MixDescriptor
}

// SignDescriptor signs and serializes the descriptor with the provided signing
// key.
func SignDescriptor(signingKey *eddsa.PrivateKey, base *pki.MixDescriptor) (string, error) {
	d := new(nodeDescriptor)
	d.MixDescriptor = *base
	d.Version = nodeDescriptorVersion

	// Serialize the descriptor.
	payload, err := json.Marshal(d)
	if err != nil {
		return "", err
	}

	// Sign the descriptor.
	k := jose.SigningKey{
		Algorithm: jose.EdDSA,
		Key:       *signingKey.InternalPtr(),
	}
	signer, err := jose.NewSigner(k, nil)
	if err != nil {
		return "", err
	}
	signed, err := signer.Sign(payload)
	if err != nil {
		return "", err
	}

	// Serialize the key, descriptor and signature.
	return signed.CompactSerialize()
}

// VerifyAndParseDescriptor verifies the signature and deserializes the
// descriptor.  MixDescriptors returned from this routine are guaranteed
// to have been correctly self signed by the IdentityKey listed in the
// MixDescriptor.
func VerifyAndParseDescriptor(b []byte, epoch uint64) (*pki.MixDescriptor, error) {
	signed, err := jose.ParseSigned(string(b))
	if err != nil {
		return nil, err
	}

	// So the descriptor is going to be signed by the node's key, which may
	// be new to the authority (which is doing the decoding).   In an ideal
	// world this is where embedding the public key in the header solves this
	// problem, but the library doesn't support doing so for EdDSA signatures.
	//
	// Since the descriptors themselves include (perhaps redundantly) a copy
	// of the IdentityKey used to sign the descriptor, we can reach into
	// the unverified payload to pull it out instead.
	//
	// This is wasteful on the CPU side since it's de-serializing the payload
	// twice, but this isn't a critical path operation, nor is the non-voting
	// authority something that will do this a lot.
	if len(signed.Signatures) != 1 {
		return nil, fmt.Errorf("nonvoting: Expected 1 signature, got: %v", len(signed.Signatures))
	}
	alg := signed.Signatures[0].Header.Algorithm
	if alg != "EdDSA" {
		return nil, fmt.Errorf("nonvoting: Unsupported signature algorithm: '%v'", alg)
	}
	candidatePk, err := extractSignedDescriptorPublicKey(b)
	if err != nil {
		return nil, err
	}

	// Verify that the descriptor is signed by the key in the header.
	payload, err := signed.Verify(*candidatePk.InternalPtr())
	if err != nil {
		return nil, err
	}

	// Parse the payload.
	d := new(nodeDescriptor)
	if err = json.Unmarshal(payload, d); err != nil {
		return nil, err
	}

	// Ensure the descriptor is well formed.
	if d.Version != nodeDescriptorVersion {
		return nil, fmt.Errorf("nonvoting: Invalid Descriptor Version: '%v'", d.Version)
	}
	if err = IsDescriptorWellFormed(&d.MixDescriptor, epoch); err != nil {
		return nil, err
	}

	// And as the final check, ensure that the key embedded in the descriptor
	// matches the key we teased out of the payload, that we used to validate
	// the signature.
	if !candidatePk.Equal(d.IdentityKey) {
		return nil, fmt.Errorf("nonvoting: Descriptor signing key mismatch")
	}
	return &d.MixDescriptor, nil
}

func extractSignedDescriptorPublicKey(b []byte) (*eddsa.PublicKey, error) {
	// Per RFC 7515:
	//
	// In the JWS Compact Serialization, a JWS is represented as the
	// concatenation:
	//
	//   BASE64URL(UTF8(JWS Protected Header)) || '.' ||
	//   BASE64URL(JWS Payload) || '.' ||
	//   BASE64URL(JWS Signature)
	//
	// The JOSE library used doesn't support embedding EdDSA JWK Public Keys
	// so this reaches into the (unverified) payload, to pull out the
	// descriptor's PublicKey.

	spl := bytes.Split(b, []byte{'.'})
	if len(spl) != 3 {
		return nil, fmt.Errorf("nonvoting: Splitting at '.' returned unexpected number of sections: %v", len(spl))
	}
	payload, err := base64.RawURLEncoding.DecodeString(string(spl[1]))
	if err != nil {
		return nil, fmt.Errorf("nonvoting: (Early) Failed to decode: %v", err)
	}
	d := new(nodeDescriptor)
	if err = json.Unmarshal(payload, d); err != nil {
		return nil, fmt.Errorf("nonvoting: (Early) Failed to deserialize: %v", err)
	}
	candidatePk := d.IdentityKey
	if candidatePk == nil {
		return nil, fmt.Errorf("nonvoting: (Early) Descriptor missing IdentityKey")
	}
	return candidatePk, nil
}

// IsDescriptorWellFormed validates the descriptor and returns a descriptive
// error iff there are any problems that would make it unusable as part of
// a PKI Document.
func IsDescriptorWellFormed(d *pki.MixDescriptor, epoch uint64) error {
	if d.Name == "" {
		return fmt.Errorf("nonvoting: Descriptor missing Name")
	}
	if len(d.Name) > constants.NodeIDLength {
		return fmt.Errorf("nonvoting: Descriptor Name '%v' exceeds max length", d.Name)
	}
	if d.LinkKey == nil {
		return fmt.Errorf("nonvoting: Descriptor missing LinkKey")
	}
	if d.IdentityKey == nil {
		return fmt.Errorf("nonvoting: Descriptor missing IdentityKey")
	}
	if d.MixKeys[epoch] == nil {
		return fmt.Errorf("nonvoting: Descriptor missing MixKey[%v]", epoch)
	}
	for e := range d.MixKeys {
		// TODO: Should this check that the epochs in MixKey are sequential?
		if e < epoch || e >= epoch+3 {
			return fmt.Errorf("nonvoting: Descriptor contains MixKey for invalid epoch: %v", d)
		}
	}
	if len(d.Addresses) == 0 {
		return fmt.Errorf("nonvoting: Descriptor missing Addresses")
	}
	for _, v := range d.Addresses {
		if err := utils.EnsureAddrIPPort(v); err != nil {
			return fmt.Errorf("nonvoting: Descriptor containx invalid Address '%v': %v", v, err)
		}
	}
	if d.Layer != pki.LayerProvider && d.Layer != 0 {
		return fmt.Errorf("nonvoting: Descriptor self-assigned Layer: '%v'", d.Layer)
	}
	return nil
}

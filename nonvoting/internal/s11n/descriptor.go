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
	"fmt"
	"net"
	"strconv"

	"github.com/katzenpost/core/crypto/eddsa"
	"github.com/katzenpost/core/pki"
	"github.com/katzenpost/core/sphinx/constants"
	"github.com/ugorji/go/codec"
	"golang.org/x/net/idna"
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
	var payload []byte
	enc := codec.NewEncoderBytes(&payload, jsonHandle)
	if err := enc.Encode(d); err != nil {
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
		if err == jose.ErrCryptoFailure {
			err = fmt.Errorf("nonvoting: Invalid descriptor signature")
		}
		return nil, err
	}

	// Parse the payload.
	d := new(nodeDescriptor)
	dec := codec.NewDecoderBytes(payload, jsonHandle)
	if err = dec.Decode(d); err != nil {
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
	//
	// XXX: Doing things this way, decodes the same object twice, once
	// prior to validating the signature, and once after, which is
	// inefficient, but this shouldn't be a critical path operation.

	spl := bytes.Split(b, []byte{'.'})
	if len(spl) != 3 {
		return nil, fmt.Errorf("nonvoting: Splitting at '.' returned unexpected number of sections: %v", len(spl))
	}
	payload, err := base64.RawURLEncoding.DecodeString(string(spl[1]))
	if err != nil {
		return nil, fmt.Errorf("nonvoting: (Early) Failed to decode: %v", err)
	}
	d := new(nodeDescriptor)
	dec := codec.NewDecoderBytes(payload, jsonHandle)
	if err = dec.Decode(d); err != nil {
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
	for transport, addrs := range d.Addresses {
		if len(addrs) == 0 {
			return fmt.Errorf("nonvoting: Descriptor contains empty Address list for transport '%v'", transport)
		}

		var expectedIPVer int
		switch transport {
		case pki.TransportInvalid:
			return fmt.Errorf("nonvoting: Descriptor contains invalid Transport")
		case pki.TransportTCPv4:
			expectedIPVer = 4
		case pki.TransportTCPv6:
			expectedIPVer = 6
		default:
			// Unknown transports are only supported between the client and
			// provider.
			if d.Layer != pki.LayerProvider {
				return fmt.Errorf("nonvoting: Non-provider published Transport '%v'", transport)
			}
			if transport != pki.TransportTCP {
				// Ignore transports that don't have validation logic.
				continue
			}
		}

		// Validate all addresses belonging to the TCP variants.
		for _, v := range addrs {
			h, p, err := net.SplitHostPort(v)
			if err != nil {
				return fmt.Errorf("nonvoting: Descriptor contains invalid address ['%v']'%v': %v", transport, v, err)
			}
			if len(h) == 0 {
				return fmt.Errorf("nonvoting: Descriptor contains invalid address ['%v']'%v'", transport, v)
			}
			if port, err := strconv.ParseUint(p, 10, 16); err != nil {
				return fmt.Errorf("nonvoting: Descriptor contains invalid address ['%v']'%v': %v", transport, v, err)
			} else if port == 0 {
				return fmt.Errorf("nonvoting: Descriptor contains invalid address ['%v']'%v': port is 0", transport, v)
			}
			switch expectedIPVer {
			case 4, 6:
				if ver, err := getIPVer(h); err != nil {
					return fmt.Errorf("nonvoting: Descriptor contains invalid address ['%v']'%v': %v", transport, v, err)
				} else if ver != expectedIPVer {
					return fmt.Errorf("nonvoting: Descriptor contains invalid address ['%v']'%v': IP version mismatch", transport, v)
				}
			default:
				// This must be TransportTCP or something else that supports
				// "sensible" DNS style hostnames.  Validate that they are
				// at least somewhat well formed.
				if _, err := idna.Lookup.ToASCII(h); err != nil {
					return fmt.Errorf("nonvoting: Descriptor contains invalid address ['%v']'%v': %v", transport, v, err)
				}
			}
		}
	}
	if len(d.Addresses[pki.TransportTCPv4]) == 0 {
		return fmt.Errorf("nonvoting: Descriptor contains no TCPv4 addresses")
	}
	switch d.Layer {
	case 0:
		if d.Kaetzchen != nil {
			return fmt.Errorf("nonvoting: Descriptor contains Kaetzchen when a mix")
		}
	case pki.LayerProvider:
		if err := validateKaetzchen(d.Kaetzchen); err != nil {
			return fmt.Errorf("nonvoting: Descriptor contains invalid Kaetzchen block: %v", err)
		}
	default:
		return fmt.Errorf("nonvoting: Descriptor self-assigned Layer: '%v'", d.Layer)
	}
	return nil
}

func validateKaetzchen(m map[string]map[string]interface{}) error {
	const keyEndpoint = "endpoint"

	if m == nil {
		return nil
	}

	for capa, params := range m {
		if len(capa) == 0 {
			return fmt.Errorf("capability lenght out of bounds")
		}
		if params == nil {
			return fmt.Errorf("capability '%v' has no parameters", capa)
		}

		// Ensure that an endpoint is specified.
		var ep string
		if v, ok := params[keyEndpoint]; !ok {
			return fmt.Errorf("capaiblity '%v' provided no endpoint", capa)
		} else if ep, ok = v.(string); !ok {
			return fmt.Errorf("capability '%v' invalid endpoint type: %T", capa, v)
		}
		// XXX: Should this enforce formating?
		if len(ep) == 0 || len(ep) > constants.RecipientIDLength {
			return fmt.Errorf("capability '%v' invalid endpoint, length out of bounds", capa)
		}

		// Note: This explicitly does not enforce endpoint uniqueness, because
		// it is conceivable that a single endpoint can service multiple
		// request types.
	}

	return nil
}

func getIPVer(h string) (int, error) {
	ip := net.ParseIP(h)
	if ip != nil {
		switch {
		case ip.To4() != nil:
			return 4, nil
		case ip.To16() != nil:
			return 6, nil
		default:
		}
	}
	return 0, fmt.Errorf("address is not an IP")
}

// descriptor.go - Katzenpost authority descriptor s11n.
// Copyright (C) 2022  Yawning Angel, masala, David Stainton
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

// Package pki provides the mix network PKI related interfaces and serialization routines

package pki

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net"
	"strconv"

	"github.com/fxamacker/cbor/v2"
	"golang.org/x/net/idna"

	"github.com/katzenpost/katzenpost/core/crypto/cert"
	"github.com/katzenpost/katzenpost/core/crypto/ecdh"
	"github.com/katzenpost/katzenpost/core/crypto/sign"
	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/katzenpost/core/wire"
)

const (
	DescriptorVersion = "v0"
)

// MixDescriptor is a description of a given Mix or Provider (node).
type MixDescriptor struct {
	// Name is the human readable (descriptive) node identifier.
	Name string

	// Epoch is the Epoch in which this descriptor was created
	Epoch uint64

	// IdentityKey is the node's identity (signing) key.
	IdentityKey sign.PublicKey

	// Signature is the raw cert.Signature over the serialized MixDescriptor
	Signature *cert.Signature `json:"-",cbor:"-"`

	// LinkKey is the node's wire protocol public key.
	LinkKey wire.PublicKey

	// MixKeys is a map of epochs to Sphinx keys.
	MixKeys map[uint64]*ecdh.PublicKey

	// Addresses is the map of transport to address combinations that can
	// be used to reach the node.
	Addresses map[Transport][]string

	// Kaetzchen is the map of provider autoresponder agents by capability
	// to parameters.
	Kaetzchen map[string]map[string]interface{} `json:",omitempty"`

	// Layer is the topology layer.
	Layer uint8

	// LoadWeight is the node's load balancing weight (unused).
	LoadWeight uint8

	// AuthenticationType is the authentication mechanism required
	AuthenticationType string

	// Version uniquely identifies the descriptor format as being for the
	// specified version so that it can be rejected if the format changes.
	Version string
}

// String returns a human readable MixDescriptor suitable for terse logging.
func (d *MixDescriptor) String() string {
	kaetzchen := ""
	if len(d.Kaetzchen) > 0 {
		kaetzchen = fmt.Sprintf("%v", d.Kaetzchen)
	}
	bs := d.IdentityKey.Sum256()
	identity := base64.StdEncoding.EncodeToString(bs[:])
	s := fmt.Sprintf("{%s %s %v", d.Name, identity, d.Addresses)
	s += kaetzchen + d.AuthenticationType + "}"
	return s
}

// UnmarshalBinary implements encoding.BinaryUnmarshaler interface
func (d *MixDescriptor) UnmarshalBinary(data []byte) error {
	// extract the embedded IdentityKey and verify it signs the payload
	certified, err := cert.GetCertified(data)
	if err != nil {
		return err
	}

	// Instantiate concrete instances so we deserialize into the right types
	_, idPublicKey := cert.Scheme.NewKeypair()
	d.IdentityKey = idPublicKey
	linkPriv := wire.DefaultScheme.GenerateKeypair(rand.Reader)
	d.LinkKey = linkPriv.PublicKey()

	// encoding type is cbor
	err = cbor.Unmarshal(certified, d)
	if err != nil {
		return err
	}
	_, err = cert.Verify(d.IdentityKey, data)
	if err != nil {
		return err
	}
	idPublic := d.IdentityKey.Sum256()
	sig, err := cert.GetSignature(idPublic[:], data)
	if err != nil {
		return err
	}
	d.Signature = sig
	return nil
}

// MarshalBinary
func (d *MixDescriptor) MarshalBinary() (data []byte, err error) {
	// reconstruct a serialized certificate from the detached Signature
	// copy the type
	type t MixDescriptor
	rawDesc, err := cbor.Marshal((*t)(d))
	if err != nil {
		return nil, err
	}

	// If the descriptor was signed, add the Signature
	signatures := make(map[[32]byte]cert.Signature)
	if d.Signature == nil {
		signatures[d.IdentityKey.Sum256()] = *d.Signature
	}
	certified := cert.Certificate{
		Version:    cert.CertVersion,
		Expiration: d.Epoch + 5,
		KeyType:    d.IdentityKey.KeyType(),
		Certified:  rawDesc,
		Signatures: signatures,
	}
	return certified.Marshal()
}

// SignDescriptor signs and serializes the descriptor with the provided signing
// key.
func SignDescriptor(signer cert.Signer, verifier cert.Verifier, desc *MixDescriptor) ([]byte, error) {
	// Serialize the descriptor.
	type t MixDescriptor
	payload, err := cbor.Marshal((*t)(desc))
	if err != nil {
		return nil, err
	}

	// Sign the descriptor. Descriptor will become valid in the next epoch, for 3 epochs.
	epoch, _, _ := epochtime.Now()
	signed, err := cert.Sign(signer, verifier, payload, epoch+5)
	if err != nil {
		return nil, err
	}
	return signed, nil
}

// VerifyDescriptor parses a self-signed MixDescriptor and returns an instance
// of MixDescriptor or error
func VerifyDescriptor(rawDesc []byte) (*MixDescriptor, error) {
	// make a MixDescriptor and initialize throwaway concrete instances so
	// that rawDesc will deserialize into the right type
	d := new(MixDescriptor)
	_, idPubKey := cert.Scheme.NewKeypair()
	linkPriv := wire.DefaultScheme.GenerateKeypair(rand.Reader)
	d.IdentityKey = idPubKey
	d.LinkKey = linkPriv.PublicKey()
	err := d.UnmarshalBinary(rawDesc)
	if err != nil {
		return nil, err
	}
	if d.Version != DescriptorVersion {
		return nil, fmt.Errorf("Invalid Document Version: '%v'", d.Version)
	}
	return d, nil
}

// GetVerifierFromDescriptor returns a verifier for the given
// mix descriptor certificate.
func GetVerifierFromDescriptor(rawDesc []byte) (cert.Verifier, error) {
	d := new(MixDescriptor)
	err := d.UnmarshalBinary(rawDesc)
	if err != nil {
		return nil, err
	}
	return d.IdentityKey, nil
}

// IsDescriptorWellFormed validates the descriptor and returns a descriptive
// error iff there are any problems that would make it unusable as part of
// a PKI Document.
func IsDescriptorWellFormed(d *MixDescriptor, epoch uint64) error {
	if d.Name == "" {
		return fmt.Errorf("Descriptor missing Name")
	}
	if len(d.Name) > constants.NodeIDLength {
		return fmt.Errorf("Descriptor Name '%v' exceeds max length", d.Name)
	}
	if d.LinkKey == nil {
		return fmt.Errorf("Descriptor missing LinkKey")
	}
	if d.IdentityKey == nil {
		return fmt.Errorf("Descriptor missing IdentityKey")
	}
	if d.MixKeys[epoch] == nil {
		return fmt.Errorf("Descriptor missing MixKey[%v]", epoch)
	}
	for e := range d.MixKeys {
		// TODO: Should this check that the epochs in MixKey are sequential?
		if e < epoch || e >= epoch+3 {
			return fmt.Errorf("Descriptor contains MixKey for invalid epoch: %v", d)
		}
	}
	if len(d.Addresses) == 0 {
		return fmt.Errorf("Descriptor missing Addresses")
	}
	for transport, addrs := range d.Addresses {
		if len(addrs) == 0 {
			return fmt.Errorf("Descriptor contains empty Address list for transport '%v'", transport)
		}

		var expectedIPVer int
		switch transport {
		case TransportInvalid:
			return fmt.Errorf("Descriptor contains invalid Transport")
		case TransportTCPv4:
			expectedIPVer = 4
		case TransportTCPv6:
			expectedIPVer = 6
		default:
			// Unknown transports are only supported between the client and
			// provider.
			if d.Layer != LayerProvider {
				return fmt.Errorf("Non-provider published Transport '%v'", transport)
			}
			if transport != TransportTCP {
				// Ignore transports that don't have validation logic.
				continue
			}
		}

		// Validate all addresses belonging to the TCP variants.
		for _, v := range addrs {
			h, p, err := net.SplitHostPort(v)
			if err != nil {
				return fmt.Errorf("Descriptor contains invalid address ['%v']'%v': %v", transport, v, err)
			}
			if len(h) == 0 {
				return fmt.Errorf("Descriptor contains invalid address ['%v']'%v'", transport, v)
			}
			if port, err := strconv.ParseUint(p, 10, 16); err != nil {
				return fmt.Errorf("Descriptor contains invalid address ['%v']'%v': %v", transport, v, err)
			} else if port == 0 {
				return fmt.Errorf("Descriptor contains invalid address ['%v']'%v': port is 0", transport, v)
			}
			switch expectedIPVer {
			case 4, 6:
				if ver, err := getIPVer(h); err != nil {
					return fmt.Errorf("Descriptor contains invalid address ['%v']'%v': %v", transport, v, err)
				} else if ver != expectedIPVer {
					return fmt.Errorf("Descriptor contains invalid address ['%v']'%v': IP version mismatch", transport, v)
				}
			default:
				// This must be TransportTCP or something else that supports
				// "sensible" DNS style hostnames.  Validate that they are
				// at least somewhat well formed.
				if _, err := idna.Lookup.ToASCII(h); err != nil {
					return fmt.Errorf("Descriptor contains invalid address ['%v']'%v': %v", transport, v, err)
				}
			}
		}
	}
	if len(d.Addresses[TransportTCPv4]) == 0 {
		return fmt.Errorf("Descriptor contains no TCPv4 addresses")
	}
	switch d.Layer {
	case 0:
		if d.Kaetzchen != nil {
			return fmt.Errorf("Descriptor contains Kaetzchen when a mix")
		}
	case LayerProvider:
		if err := validateKaetzchen(d.Kaetzchen); err != nil {
			return fmt.Errorf("Descriptor contains invalid Kaetzchen block: %v", err)
		}
	default:
		return fmt.Errorf("Descriptor self-assigned Layer: '%v'", d.Layer)
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

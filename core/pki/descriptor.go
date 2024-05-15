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
	"errors"
	"fmt"
	"net"
	"strconv"

	"github.com/fxamacker/cbor/v2"

	"golang.org/x/net/idna"

	"github.com/katzenpost/hpqc/hash"
	"github.com/katzenpost/hpqc/kem"
	kemschemes "github.com/katzenpost/hpqc/kem/schemes"
	"github.com/katzenpost/hpqc/nike"
	"github.com/katzenpost/hpqc/nike/schemes"
	"github.com/katzenpost/hpqc/sign"

	"github.com/katzenpost/katzenpost/core/cert"
	"github.com/katzenpost/katzenpost/core/sphinx/constants"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/katzenpost/katzenpost/loops"
)

const (
	DescriptorVersion = "v0"
)

var (
	ErrNoSignature       = errors.New("MixDescriptor has no signature")
	ErrInvalidSignature  = errors.New("MixDescriptor has an invalid signature")
	ErrTooManySignatures = errors.New("MixDescriptor has more than one signature")
)

type SignedUpload struct {
	// Signature is the signature over the serialized SignedUpload.
	Signature *cert.Signature

	// MixDescriptor is the mix descriptor.
	MixDescriptor *MixDescriptor

	// LoopStats is the mix loop statistics.
	LoopStats *loops.LoopStats
}

func (s *SignedUpload) Marshal() ([]byte, error) {
	return ccbor.Marshal(s)
}

func (s *SignedUpload) Unmarshal(data []byte) error {
	return cbor.Unmarshal(data, s)
}

func (s *SignedUpload) Sign(privKey sign.PrivateKey, pubKey sign.PublicKey) error {
	if s.Signature != nil {
		return errors.New("SignedUpload already has a signature")
	}
	blob, err := s.Marshal()
	if err != nil {
		return err
	}
	sig := &cert.Signature{
		PublicKeySum256: hash.Sum256From(pubKey),
		Payload:         privKey.Scheme().Sign(privKey, blob, nil),
	}
	s.Signature = sig
	return nil
}

func (s *SignedUpload) Verify(pubKey sign.PublicKey) bool {
	ss := &SignedUpload{
		Signature:     nil,
		MixDescriptor: s.MixDescriptor,
		LoopStats:     s.LoopStats,
	}
	blob, err := ss.Marshal()
	if err != nil {
		return false
	}

	return pubKey.Scheme().Verify(pubKey, blob, s.Signature.Payload, nil)
}

// MixDescriptor is a description of a given Mix or Provider (node).
type MixDescriptor struct {
	// Name is the human readable (descriptive) node identifier.
	Name string

	// Epoch is the Epoch in which this descriptor was created
	Epoch uint64

	// IdentityKey is the node's identity (signing) key.
	IdentityKey []byte

	// LinkKey is the node's wire protocol public key.
	LinkKey []byte

	// MixKeys is a map of epochs to Sphinx keys.
	MixKeys map[uint64][]byte

	// Addresses is the map of transport to address combinations that can
	// be used to reach the node.
	Addresses map[string][]string

	// Kaetzchen is the map of provider autoresponder agents by capability
	// to parameters.
	Kaetzchen map[string]map[string]interface{} `cbor:"omitempty"`

	// IsGatewayNode indicates that this Mix is a gateway node.
	// Essentially a gateway allows clients to interact with the mixnet.
	// This option being set to true is mutually exclusive with
	// `IsServiceNode` being set to true.
	IsGatewayNode bool

	// IsServiceNode indicates that this Mix is a service node.
	// Service nodes run services which the mixnet interacts with.
	IsServiceNode bool

	// LoadWeight is the node's load balancing weight (unused).
	LoadWeight uint8

	// AuthenticationType is the authentication mechanism required
	AuthenticationType string

	// Version uniquely identifies the descriptor format as being for the
	// specified version so that it can be rejected if the format changes.
	Version string
}

type mixdescriptor MixDescriptor

func (d *MixDescriptor) ShallowCopyWithoutSignature() *MixDescriptor {
	desc := &MixDescriptor{
		Name:               d.Name,
		Epoch:              d.Epoch,
		IdentityKey:        d.IdentityKey,
		LinkKey:            d.LinkKey,
		MixKeys:            d.MixKeys,
		Addresses:          d.Addresses,
		Kaetzchen:          d.Kaetzchen,
		Provider:           d.Provider,
		LoadWeight:         d.LoadWeight,
		AuthenticationType: d.AuthenticationType,
		Version:            d.Version,
	}

	return desc
}

func (d *MixDescriptor) UnmarshalMixKeyAsNike(epoch uint64, g *geo.Geometry) (nike.PublicKey, error) {
	s := schemes.ByName(g.NIKEName)
	if s == nil {
		panic("failed to get a NIKE scheme")
	}
	return s.UnmarshalBinaryPublicKey(d.MixKeys[epoch])
}

func (d *MixDescriptor) UnmarshalMixKeyAsKEM(epoch uint64, g *geo.Geometry) (kem.PublicKey, error) {
	k := kemschemes.ByName(g.KEMName)
	if k == nil {
		panic("failed to get a KEM scheme")
	}
	return k.UnmarshalBinaryPublicKey(d.MixKeys[epoch])
}

// String returns a human readable MixDescriptor suitable for terse logging.
func (d *MixDescriptor) String() string {
	kaetzchen := ""
	if len(d.Kaetzchen) > 0 {
		kaetzchen = fmt.Sprintf("%v", d.Kaetzchen)
	}
	id := hash.Sum256(d.IdentityKey)
	s := fmt.Sprintf("{%s %x %v", d.Name, id, d.Addresses)
	s += kaetzchen + d.AuthenticationType + "}"
	return s
}

// UnmarshalBinary implements encoding.BinaryUnmarshaler interface
func (d *MixDescriptor) UnmarshalBinary(data []byte) error {
	return cbor.Unmarshal(data, (*mixdescriptor)(d))
}

// MarshalBinary implmements encoding.BinaryMarshaler
func (d *MixDescriptor) MarshalBinary() ([]byte, error) {
	return ccbor.Marshal((*mixdescriptor)(d))
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
			// gateway.
			if !d.IsGatewayNode {
				return fmt.Errorf("Non-gateway published Transport '%v'", transport)
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
	if !d.IsServiceNode {
		if d.Kaetzchen != nil {
			return fmt.Errorf("Descriptor contains Kaetzchen when a mix")
		}
	} else {
		if err := validateKaetzchen(d.Kaetzchen); err != nil {
			return fmt.Errorf("Descriptor contains invalid Kaetzchen block: %v", err)
		}
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

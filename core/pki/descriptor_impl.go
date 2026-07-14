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

//go:build !wasm

// Package pki provides the mix network PKI related interfaces and serialization routines

package pki

import (
	"errors"
	"fmt"
	"net"

	"github.com/fxamacker/cbor/v2"

	"github.com/katzenpost/hpqc/hash"
	"github.com/katzenpost/hpqc/kem"
	kempem "github.com/katzenpost/hpqc/kem/pem"
	kemschemes "github.com/katzenpost/hpqc/kem/schemes"
	"github.com/katzenpost/hpqc/nike"
	nikepem "github.com/katzenpost/hpqc/nike/pem"
	"github.com/katzenpost/hpqc/nike/schemes"
	"github.com/katzenpost/hpqc/sign"
	signpem "github.com/katzenpost/hpqc/sign/pem"

	"github.com/katzenpost/katzenpost/core/cert"
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

type mixdescriptor MixDescriptor

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

func (d *MixDescriptor) GetRawCourierLinkKey() (string, error) {
	courierData, ok := d.KaetzchenAdvertizedData["courier"]
	if !ok {
		return "", errors.New("KaetzchenAdvertizedData does not have an entry for 'courier'")
	}
	linkPubKey, ok := courierData["linkPublicKey"]
	if !ok {
		return "", errors.New("courier data does not have an entry for linkPublicKey")
	}
	ret, ok := linkPubKey.(string)
	if !ok {
		return "", errors.New("cannot type cast courier linkPubKey into string")
	}
	return ret, nil
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

func (d *ReplicaDescriptor) DisplayWithSchemes(linkScheme kem.Scheme, identityScheme sign.Scheme, envelopeScheme nike.Scheme) string {
	idPubKey, err := identityScheme.UnmarshalBinaryPublicKey(d.IdentityKey)
	if err != nil {
		panic(err)
	}
	idKey := signpem.ToPublicPEMString(idPubKey)
	linkPubKey, err := linkScheme.UnmarshalBinaryPublicKey(d.LinkKey)
	if err != nil {
		panic(err)
	}
	linkKey := kempem.ToPublicPEMString(linkPubKey)

	envelopeKeys := []string{}
	for epoch, rawkey := range d.EnvelopeKeys {
		nikePubkey, err := envelopeScheme.UnmarshalBinaryPublicKey(rawkey)
		if err != nil {
			panic(err)
		}
		nikeKey := nikepem.ToPublicPEMString(nikePubkey, envelopeScheme)
		envelopeKeys = append(envelopeKeys, fmt.Sprintf("epoch %d -> %s", epoch, nikeKey))
	}

	return fmt.Sprintf(`ReplicaDescriptor:
Name: %s
ReplicaID: %d
Epoch: %d
IdentityKey: %s
LinkKey: %s
EnvelopeKeys: %v
Addresses: %s
`, d.Name, d.ReplicaID, d.Epoch, idKey, linkKey, envelopeKeys, d.Addresses)
}

// UnmarshalBinary implements encoding.BinaryUnmarshaler interface
func (d *ReplicaDescriptor) Unmarshal(data []byte) error {
	return cbor.Unmarshal(data, d)
}

// MarshalBinary implmements encoding.BinaryMarshaler
func (d *ReplicaDescriptor) Marshal() ([]byte, error) {
	return ccbor.Marshal(d)
}

type SignedReplicaUpload struct {
	// Signature is the signature over the serialized SignedReplicaUpload.
	Signature *cert.Signature

	// ReplicaDescriptor is the replica descriptor.
	ReplicaDescriptor *ReplicaDescriptor
}

func (s *SignedReplicaUpload) Marshal() ([]byte, error) {
	return ccbor.Marshal(s)
}

func (s *SignedReplicaUpload) Unmarshal(data []byte) error {
	return cbor.Unmarshal(data, s)
}

func (s *SignedReplicaUpload) Sign(privKey sign.PrivateKey, pubKey sign.PublicKey) error {
	if s.Signature != nil {
		return errors.New("SignedReplicaUpload already has a signature")
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

func (s *SignedReplicaUpload) Verify(pubKey sign.PublicKey) bool {
	ss := &SignedReplicaUpload{
		Signature:         nil,
		ReplicaDescriptor: s.ReplicaDescriptor,
	}
	blob, err := ss.Marshal()
	if err != nil {
		return false
	}

	return pubKey.Scheme().Verify(pubKey, blob, s.Signature.Payload, nil)
}

func (d *ReplicaDescriptor) String() string {
	if d == nil {
		return "<nil>"
	}
	return fmt.Sprintf("{%s %x %v}", d.Name, d.IdentityKey, d.Addresses)
}

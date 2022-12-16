// document.go - Mixnet PKI interfaces
// Copyright (C) 2022  David Stainton, Yawning Angel, masala.
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
	"context"
	"crypto/hmac"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/fxamacker/cbor/v2"

	"github.com/katzenpost/katzenpost/core/crypto/cert"
	"github.com/katzenpost/katzenpost/core/crypto/sign"
)

const (
	// LayerProvider is the Layer that providers list in their MixDescriptors.
	LayerProvider           = 255
	PublicKeyHashSize       = 32
	SharedRandomLength      = 40
	SharedRandomValueLength = 32

	// DocumentVersion identifies the document format version
	DocumentVersion = "v0"
)

var (
	// ErrNoDocument is the error returned when there never will be a document
	// for a given epoch.
	ErrNoDocument = errors.New("pki: requested epoch will never get a document")

	// ErrInvalidPostEpoch is the error returned when the server rejects a
	// descriptor upload for a given epoch due to time reasons.
	ErrInvalidPostEpoch = errors.New("pki: post for epoch will never succeeed")

	// TrustOnFirstUseAuth is a MixDescriptor.AuthenticationType
	TrustOnFirstUseAuth = "tofu"

	// OutOfBandAuth is a MixDescriptor.AuthenticationType
	OutOfBandAuth = "oob"
)

// Document is a PKI document.
type Document struct {
	// Epoch is the epoch for which this Document instance is valid for.
	Epoch uint64

	// GenesisEpoch is the epoch on which authorities started consensus
	GenesisEpoch uint64

	// SendRatePerMinute is the number of packets per minute a client can send.
	SendRatePerMinute uint64

	// Mu is the inverse of the mean of the exponential distribution
	// that the Sphinx packet per-hop mixing delay will be sampled from.
	Mu float64

	// MuMaxDelay is the maximum Sphinx packet per-hop mixing delay in
	// milliseconds.
	MuMaxDelay uint64

	// LambdaP is the inverse of the mean of the exponential distribution
	// that clients will sample to determine the time interval between sending
	// messages from it's FIFO egress queue or drop decoy messages if the queue
	// is empty.
	LambdaP float64

	// LambdaPMaxDelay is the maximum time interval in milliseconds.
	LambdaPMaxDelay uint64

	// LambdaL is the inverse of the mean of the exponential distribution
	// that clients will sample to determine the time interval between sending
	// decoy loop messages.
	LambdaL float64

	// LambdaLMaxDelay is the maximum time interval in milliseconds.
	LambdaLMaxDelay uint64

	// LambdaD is the inverse of the mean of the exponential distribution
	// that clients will sample to determine the time interval between sending
	// decoy drop messages.
	LambdaD float64

	// LambdaDMaxDelay is the maximum time interval in milliseconds.
	LambdaDMaxDelay uint64

	// LambdaM is the inverse of the mean of the exponential distribution
	// that mixes will sample to determine send timing of mix loop decoy traffic.
	LambdaM float64

	// LambdaMMaxDelay is the maximum send interval in milliseconds.
	LambdaMMaxDelay uint64

	// Topology is the mix network topology, excluding providers.
	Topology [][]*MixDescriptor

	// Providers is the list of providers that can interact with the mix
	// network.
	Providers []*MixDescriptor

	// Signatures holds detached Signatures from deserializing a signed Document
	Signatures map[[PublicKeyHashSize]byte]cert.Signature `cbor:"-"`

	// SharedRandomCommit used by the voting process.
	SharedRandomCommit map[[PublicKeyHashSize]byte][]byte

	// SharedRandomReveal used by the voting process.
	SharedRandomReveal map[[PublicKeyHashSize]byte][]byte

	// SharedRandomValue produced by voting process.
	SharedRandomValue []byte

	// PriorSharedRandom used by applications that need a longer lived SRV.
	PriorSharedRandom [][]byte

	// Version uniquely identifies the document format as being for the
	// specified version so that it can be rejected if the format changes.
	Version string
}

// document contains fields from Document but not the encoding.BinaryMarshaler methods
type document Document

// String returns a string representation of a Document.
func (d *Document) String() string {
	srv := base64.StdEncoding.EncodeToString(d.SharedRandomValue)
	psrv := "["
	for i, p := range d.PriorSharedRandom {
		psrv += base64.StdEncoding.EncodeToString(p)
		if i+1 < len(d.PriorSharedRandom) {
			psrv += ", "
		}
	}
	psrv += "]"

	s := fmt.Sprintf("&{Epoch: %v GenesisEpoch: %v\nSendRatePerMinute: %v Mu: %v MuMaxDelay: %v LambdaP:%v LambdaPMaxDelay:%v LambdaL:%v LambdaLMaxDelay:%v LambdaD:%v LambdaDMaxDelay:%v LambdaM: %v LambdaMMaxDelay: %v\nSharedRandomValue: %v PriorSharedRandom: %v\nTopology:\n", d.Epoch, d.GenesisEpoch, d.SendRatePerMinute, d.Mu, d.MuMaxDelay, d.LambdaP, d.LambdaPMaxDelay, d.LambdaL, d.LambdaLMaxDelay, d.LambdaD, d.LambdaDMaxDelay, d.LambdaM, d.LambdaMMaxDelay, srv, psrv)
	for l, nodes := range d.Topology {
		s += fmt.Sprintf("  [%v]{", l)
		s += fmt.Sprintf("%v", nodes)
		s += "}\n"
	}

	s += "}\n"
	s += fmt.Sprintf("Providers:[]{%v}", d.Providers)
	s += "}}"
	return s
}

// GetProvider returns the MixDescriptor for the given provider Name.
func (d *Document) GetProvider(name string) (*MixDescriptor, error) {
	for _, v := range d.Providers {
		if v.Name == name {
			return v, nil
		}
	}
	return nil, fmt.Errorf("pki: provider '%v' not found", name)
}

// GetProviderByKeyHash returns the specific provider descriptor corresponding
// to the specified IdentityKey hash.
func (d *Document) GetProviderByKeyHash(keyhash *[32]byte) (*MixDescriptor, error) {
	for _, v := range d.Providers {
		if v.IdentityKey == nil {
			return nil, fmt.Errorf("pki: document contains invalid descriptors")
		}
		idKeyHash := v.IdentityKey.Sum256()
		if hmac.Equal(idKeyHash[:], keyhash[:]) {
			return v, nil
		}
	}
	return nil, fmt.Errorf("pki: provider not found")
}

// GetMix returns the MixDescriptor for the given mix Name.
func (d *Document) GetMix(name string) (*MixDescriptor, error) {
	for _, l := range d.Topology {
		for _, v := range l {
			if v.Name == name {
				return v, nil
			}
		}
	}
	return nil, fmt.Errorf("pki: mix '%v' not found", name)
}

// GetMixesInLayer returns all the mix descriptors for a given layer.
func (d *Document) GetMixesInLayer(layer uint8) ([]*MixDescriptor, error) {
	if len(d.Topology)-1 < int(layer) {
		return nil, fmt.Errorf("pki: invalid layer: '%v'", layer)
	}
	return d.Topology[layer], nil
}

// GetMixByKey returns the specific mix descriptor corresponding
// to the specified IdentityKey hash.
func (d *Document) GetMixByKeyHash(keyhash *[32]byte) (*MixDescriptor, error) {
	for _, l := range d.Topology {
		for _, v := range l {
			if v.IdentityKey == nil {
				return nil, fmt.Errorf("pki: document contains invalid descriptors")
			}
			idKeyHash := v.IdentityKey.Sum256()
			if hmac.Equal(idKeyHash[:], keyhash[:]) {
				return v, nil
			}
		}
	}
	return nil, fmt.Errorf("pki: mix not found")
}

// GetNode returns the specific descriptor corresponding to the specified
// node Name.
func (d *Document) GetNode(name string) (*MixDescriptor, error) {
	if m, err := d.GetMix(name); err == nil {
		return m, nil
	}
	if m, err := d.GetProvider(name); err == nil {
		return m, nil
	}
	return nil, fmt.Errorf("pki: node not found")
}

// GetNodeByKeyHash returns the specific descriptor corresponding to the
// specified IdentityKey hash.
func (d *Document) GetNodeByKeyHash(keyhash *[32]byte) (*MixDescriptor, error) {
	if m, err := d.GetMixByKeyHash(keyhash); err == nil {
		return m, nil
	}
	if m, err := d.GetProviderByKeyHash(keyhash); err == nil {
		return m, nil
	}
	return nil, fmt.Errorf("pki: node not found")
}

// Transport is a link transport protocol.
type Transport string

var (
	// TransportInvalid is the invalid transport.
	TransportInvalid Transport

	// TransportTCP is TCP, with the IP version determined by the results of
	// a name server lookup.
	TransportTCP Transport = "tcp"

	// TransportTCPv4 is TCP over IPv4.
	TransportTCPv4 Transport = "tcp4"

	// TransportTCPv6 is TCP over IPv6.
	TransportTCPv6 Transport = "tcp6"

	// InternalTransports is the list of transports used for non-client related
	// communications.
	InternalTransports = []Transport{TransportTCPv4, TransportTCPv6}

	// ClientTransports is the list of transports used by default for client
	// to provider communication.
	ClientTransports = []Transport{TransportTCP, TransportTCPv4, TransportTCPv6}
)

// Client is the abstract interface used for PKI interaction.
type Client interface {
	// Get returns the PKI document along with the raw serialized form for the provided epoch.
	Get(ctx context.Context, epoch uint64) (*Document, []byte, error)

	// Post posts the node's descriptor to the PKI for the provided epoch.
	Post(ctx context.Context, epoch uint64, signingPrivateKey sign.PrivateKey, signingPublicKey sign.PublicKey, d *MixDescriptor) error

	// Deserialize returns PKI document given the raw bytes.
	Deserialize(raw []byte) (*Document, error)
}

// FromPayload deserializes, then verifies a Document, and returns the Document or error.
func FromPayload(verifier cert.Verifier, payload []byte) (*Document, error) {
	verified, err := cert.Verify(verifier, payload)
	if err != nil {
		return nil, err
	}
	d := new(Document)
	if err := d.UnmarshalBinary(verified); err != nil {
		return nil, err
	}
	return d, nil
}

// SignDocument signs and serializes the document with the provided signing key.
func SignDocument(signer cert.Signer, verifier cert.Verifier, d *Document) ([]byte, error) {
	d.Version = DocumentVersion
	// Serialize the document.
	payload, err := cbor.Marshal((*document)(d))
	if err != nil {
		return nil, err
	}
	// Sign the document.
	return cert.Sign(signer, verifier, payload, d.Epoch+5)
}

// MultiSignDocument signs and serializes the document with the provided signing key, adding the signature to the existing signatures.
func MultiSignDocument(signer cert.Signer, verifier cert.Verifier, peerSignatures []*cert.Signature, verifiers map[[32]byte]cert.Verifier, d *Document) ([]byte, error) {
	d.Version = DocumentVersion

	// Serialize the document.
	payload, err := cbor.Marshal((*document)(d))
	if err != nil {
		return nil, err
	}

	// Sign the document.
	signed, err := cert.Sign(signer, verifier, payload, d.Epoch+5)
	if err != nil {
		return nil, err
	}

	// attach peer signatures
	for _, signature := range peerSignatures {
		s := signature.PublicKeySum256
		verifier := verifiers[s]
		signed, err = cert.AddSignature(verifier, *signature, signed)
		if err != nil {
			return nil, err
		}
	}

	return signed, nil
}

// VerifyAndParseDocument verifies the signature and deserializes the document.
func VerifyAndParseDocument(b []byte, verifier cert.Verifier) (*Document, error) {
	// Parse the payload.
	d := new(Document)
	err := d.UnmarshalBinary(b)
	if err != nil {
		return nil, err
	}


	// Check the Document has met requirements.
	if err = IsDocumentWellFormed(d); err != nil {
		return nil, err
	}

	// Fixup the Layer field in all the Topology MixDescriptors.
	for layer, nodes := range d.Topology {
		for _, desc := range nodes {
			desc.Layer = uint8(layer)
		}
	}

	return d, nil
}

// IsDocumentWellFormed validates the document and returns a descriptive error
// iff there are any problems that invalidates the document.
func IsDocumentWellFormed(d *Document) error {
	// Ensure the document is well formed.
	if d.Version != DocumentVersion {
		return fmt.Errorf("Invalid Document Version: '%v'", d.Version)
	}
	if d.GenesisEpoch == 0 {
		return fmt.Errorf("Document has invalid GenesisEpoch")
	}
	if len(d.PriorSharedRandom) == 0 && d.GenesisEpoch != d.Epoch {
		return fmt.Errorf("Document has invalid PriorSharedRandom")
	}
	// If there is a SharedRandomCommit, verify the Epoch contained in
	// SharedRandomCommit matches the Epoch in the Document.
	// XXX: Verify() each SharedRandom and its signature
	for _, commit := range d.SharedRandomCommit {
		if len(commit) == SharedRandomLength {
			srvEpoch := binary.BigEndian.Uint64(commit[0:8])
			if srvEpoch != d.Epoch {
				return fmt.Errorf("Document with invalid Epoch in SharedRandomCommit")
			}
		} else {
			return fmt.Errorf("Document has invalid SharedRandomCommit")
		}
	}
	// Votes and Consensus differ in that a Consensus has a SharedRandomValue and the set of SharedRandomCommit and SharedRandomReveals that produced it; otherwise there must be only one SharedRandomCommit
	switch len(d.SharedRandomValue) {
	case SharedRandomValueLength:
	case 0:
		// if there is no SharedRandomValue, this document must be a
		// Vote and have only one SharedRandomCommit
		if len(d.SharedRandomCommit) != 1 {
			return fmt.Errorf("Document has invalid SharedRandomCommit")
		}
	default:
		return fmt.Errorf("Document has invalid SharedRandomValue")
	}
	if len(d.Topology) == 0 {
		return fmt.Errorf("Document contains no Topology")
	}
	pks := make(map[[sign.PublicKeyHashSize]byte]bool)
	for layer, nodes := range d.Topology {
		if len(nodes) == 0 {
			return fmt.Errorf("Document Topology layer %d contains no nodes", layer)
		}
		for _, desc := range nodes {
			if err := IsDescriptorWellFormed(desc, d.Epoch); err != nil {
				return err
			}
			pk := desc.IdentityKey.Sum256()
			if _, ok := pks[pk]; ok {
				return fmt.Errorf("Document contains multiple entries for %v", desc.IdentityKey)
			}
			pks[pk] = true
		}
	}
	if len(d.Providers) == 0 {
		return fmt.Errorf("Document contains no Providers")
	}
	for _, desc := range d.Providers {
		if err := IsDescriptorWellFormed(desc, d.Epoch); err != nil {
			return err
		}
		if desc.Layer != LayerProvider {
			return fmt.Errorf("Document lists %v as a Provider with layer %v", desc.IdentityKey, desc.Layer)
		}
		pk := desc.IdentityKey.Sum256()
		if _, ok := pks[pk]; ok {
			return fmt.Errorf("Document contains multiple entries for %v", desc.IdentityKey)
		}
		pks[pk] = true
	}

	return nil
}

// MarshalBinary implements encoding.BinaryMarshaler interface
// and wraps a Document with a cert.Certificate
func (d *Document) MarshalBinary() ([]byte, error) {
	// Serialize Document without calling this method
	payload, err := cbor.Marshal((*document)(d))
	if err != nil {
		return nil, err
	}
	pk, _ := cert.Scheme.NewKeypair()
	certified := cert.Certificate{
		Version:    cert.CertVersion,
		Expiration: d.Epoch + 5,
		KeyType:    pk.KeyType(),
		Certified:  payload,
		Signatures: d.Signatures,
	}
	b, err := certified.Marshal()
	if err != nil {
		panic(err)
	}
	return b, err
}

// UnmarshalBinary implements encoding.BinaryUnmarshaler interface
// and populates Document with detached Signatures
func (d *Document) UnmarshalBinary(data []byte) error {
	certified, err := cert.GetCertified(data)
	if err != nil {
		panic(err)
		return err
	}
	sigs, err := cert.GetSignatures(data)
	if err != nil {
		panic(err)
		return err
	}
	if len(sigs) == 0 {
		panic("No sigs")
	}
	err = cbor.Unmarshal(certified, (*document)(d))
	if err != nil {
		panic(err)
		return err
	}
	for _, s := range sigs {
		d.Signatures[s.PublicKeySum256] = s
	}
	return nil
}

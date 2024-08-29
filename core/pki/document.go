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
	"crypto/hmac"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/fxamacker/cbor/v2"
	"golang.org/x/crypto/blake2b"

	"github.com/katzenpost/hpqc/hash"
	"github.com/katzenpost/hpqc/sign"

	"github.com/katzenpost/katzenpost/core/cert"
)

const (
	// LayerGateway is the Layer that gateways list in their MixDescriptors.
	LayerGateway = 255

	// LayerService is the Layer that service nodes list in their MixDescriptors.
	LayerService = 254

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

	// ErrInvalidEpoch is the error to return when the document epoch is invalid.
	ErrInvalidEpoch = errors.New("invalid document epoch")

	// ErrDocumentNotSigned is the error returned when deserializing an unsigned
	// document
	ErrDocumentNotSigned = errors.New("document not signed")

	// TrustOnFirstUseAuth is a MixDescriptor.AuthenticationType
	TrustOnFirstUseAuth = "tofu"

	// OutOfBandAuth is a MixDescriptor.AuthenticationType
	OutOfBandAuth = "oob"

	// Create reusable EncMode interface with immutable options, safe for concurrent use.
	ccbor cbor.EncMode
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

	// LambdaG is the inverse of the mean of the exponential distribution
	// that mixes will sample to determine send timing of gateway node loop decoy traffic.
	LambdaG float64

	// LambdaMMaxDelay is the maximum send interval in milliseconds.
	LambdaGMaxDelay uint64

	// Topology is the mix network topology, excluding providers.
	Topology [][]*MixDescriptor

	// GatewayNodes is the list of nodes that can allow clients to interact
	// with the mix network.
	GatewayNodes []*MixDescriptor

	// ServiceNodes is the list of nodes that can allow services to interact
	// with tehe mix network.
	ServiceNodes []*MixDescriptor

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

	// SphinxGeometryHash is used to ensure all mixnet actors have the same
	// Sphinx Geometry.
	SphinxGeometryHash []byte

	// Version uniquely identifies the document format as being for the
	// specified version so that it can be rejected if the format changes.
	Version string

	// PKISignatureScheme specifies the cryptographic signature scheme
	PKISignatureScheme string
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
	s += fmt.Sprintf("GatewayNodes:[]{%v}", d.GatewayNodes)
	s += "}}\n"

	s += "}\n"
	s += fmt.Sprintf("ServiceNodes:[]{%v}", d.ServiceNodes)
	s += "}}\n"

	for id, signedCommit := range d.SharedRandomCommit {
		commit, err := cert.GetCertified(signedCommit)
		if err != nil {
			panic("corrupted document")
		}
		src := base64.StdEncoding.EncodeToString(commit)
		s += fmt.Sprintf("  SharedRandomCommit: %x, %s\n", id, src)
	}
	for id, signedReveal := range d.SharedRandomReveal {
		reveal, err := cert.GetCertified(signedReveal)
		if err != nil {
			panic("corrupted document")
		}
		srr := base64.StdEncoding.EncodeToString(reveal)
		s += fmt.Sprintf("  SharedRandomReveal: %x, %s\n", id, srr)
	}

	return s
}

// GetGateway returns the MixDescriptor for the given gateway Name.
func (d *Document) GetGateway(name string) (*MixDescriptor, error) {
	for _, v := range d.GatewayNodes {
		if v.Name == name {
			return v, nil
		}
	}
	return nil, fmt.Errorf("pki: gateway node '%v' not found", name)
}

// GetService returns the MixDescriptor for the given service Name.
func (d *Document) GetServiceNode(name string) (*MixDescriptor, error) {
	for _, v := range d.ServiceNodes {
		if v.Name == name {
			return v, nil
		}
	}
	return nil, fmt.Errorf("pki: service node '%v' not found", name)
}

// GetGatewayByKeyHash returns the specific gateway descriptor corresponding
// to the specified IdentityKey hash.
func (d *Document) GetGatewayByKeyHash(keyhash *[32]byte) (*MixDescriptor, error) {
	for _, v := range d.GatewayNodes {
		if v.IdentityKey == nil {
			return nil, fmt.Errorf("pki: document contains invalid descriptors")
		}
		idKeyHash := hash.Sum256(v.IdentityKey)
		if hmac.Equal(idKeyHash[:], keyhash[:]) {
			return v, nil
		}
	}
	return nil, fmt.Errorf("pki: gateway not found")
}

// GetServiceByKeyHash returns the specific service descriptor corresponding
// to the specified IdentityKey hash.
func (d *Document) GetServiceNodeByKeyHash(keyhash *[32]byte) (*MixDescriptor, error) {
	for _, v := range d.ServiceNodes {
		if v.IdentityKey == nil {
			return nil, fmt.Errorf("pki: document contains invalid descriptors")
		}
		idKeyHash := hash.Sum256(v.IdentityKey)
		if hmac.Equal(idKeyHash[:], keyhash[:]) {
			return v, nil
		}
	}
	return nil, fmt.Errorf("pki: service not found")
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

// GetMixLayer returns the assigned layer for the given mix from Topology
func (d *Document) GetMixLayer(keyhash *[32]byte) (uint8, error) {
	for _, p := range d.GatewayNodes {
		idKeyHash := hash.Sum256(p.IdentityKey)
		if hmac.Equal(idKeyHash[:], keyhash[:]) {
			return LayerGateway, nil
		}
	}
	for _, p := range d.ServiceNodes {
		idKeyHash := hash.Sum256(p.IdentityKey)
		if hmac.Equal(idKeyHash[:], keyhash[:]) {
			return LayerService, nil
		}
	}
	for n, l := range d.Topology {
		for _, v := range l {
			idKeyHash := hash.Sum256(v.IdentityKey)
			if hmac.Equal(idKeyHash[:], keyhash[:]) {
				return uint8(n), nil
			}
		}
	}
	return 0, fmt.Errorf("pki: mix '%v' not found", keyhash)
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
			idKeyHash := hash.Sum256(v.IdentityKey)
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
	if m, err := d.GetGateway(name); err == nil {
		return m, nil
	}
	if m, err := d.GetServiceNode(name); err == nil {
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
	if m, err := d.GetGatewayByKeyHash(keyhash); err == nil {
		return m, nil
	}
	if m, err := d.GetServiceNodeByKeyHash(keyhash); err == nil {
		return m, nil
	}
	return nil, fmt.Errorf("pki: node not found")
}

var (
	// TransportInvalid is the invalid transport.
	TransportInvalid string

	// TransportTCP is TCP, with the IP version determined by the results of
	// a name server lookup.
	TransportTCP string = "tcp"

	// TransportTCPv4 is TCP over IPv4.
	TransportTCPv4 string = "tcp4"

	// TransportTCPv6 is TCP over IPv6.
	TransportTCPv6 string = "tcp6"

	// InternalTransports is the list of transports used for non-client related
	// communications.
	InternalTransports = []string{TransportTCPv4, TransportTCPv6}

	// ClientTransports is the list of transports used by default for client
	// to provider communication.
	ClientTransports = []string{TransportTCP, TransportTCPv4, TransportTCPv6}
)

// FromPayload deserializes, then verifies a Document, and returns the Document or error.
func FromPayload(verifier sign.PublicKey, payload []byte) (*Document, error) {
	_, err := cert.Verify(verifier, payload)
	if err != nil {
		return nil, err
	}
	d := new(Document)
	if err := d.UnmarshalBinary(payload); err != nil {
		return nil, err
	}
	return d, nil
}

// SignDocument signs and serializes the document with the provided signing key.
func SignDocument(signer sign.PrivateKey, verifier sign.PublicKey, d *Document) ([]byte, error) {
	d.Version = DocumentVersion
	// Marshal the document including any existing d.Signatures
	certified, err := d.MarshalBinary()
	if err != nil {
		panic("failed to marshal our own doc")
	}
	recertified, err := cert.SignMulti(signer, verifier, certified)
	if err != nil {
		return nil, err
		//panic("failed to add our own sig to certified doc")
	}
	// re-deserialize the recertified certificate to extract our own signature
	// to d.Signatures etc:
	err = d.UnmarshalBinary(recertified)
	if err != nil {
		return nil, err
	}
	return recertified, nil
}

// MultiSignDocument signs and serializes the document with the provided signing key, adding the signature to the existing signatures.
func MultiSignDocument(signer sign.PrivateKey, verifier sign.PublicKey, peerSignatures []*cert.Signature, verifiers map[[32]byte]sign.PublicKey, d *Document) ([]byte, error) {
	d.Version = DocumentVersion

	// Serialize the document.
	payload, err := ccbor.Marshal((*document)(d))
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

// ParseDocument deserializes the document.
func ParseDocument(b []byte) (*Document, error) {
	// Parse the payload.
	d := new(Document)
	err := d.UnmarshalBinary(b)
	if err != nil {
		return nil, err
	}
	return d, nil
}

// IsDocumentWellFormed validates the document and returns a descriptive error
// iff there are any problems that invalidates the document.
func IsDocumentWellFormed(d *Document, verifiers []sign.PublicKey) error {
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
	vmap := make(map[[PublicKeyHashSize]byte]sign.PublicKey)
	for _, v := range verifiers {
		vmap[hash.Sum256From(v)] = v
	}

	for id, signedCommit := range d.SharedRandomCommit {
		verifier, ok := vmap[id]
		if !ok {
			return fmt.Errorf("Document has unknown verifier on a SharedRandomCommit")
		}
		commit, err := cert.Verify(verifier, signedCommit)
		if err != nil {
			return fmt.Errorf("Document has invalid signed SharedRandomCommit")
		}
		if len(commit) == SharedRandomLength {
			srvEpoch := binary.BigEndian.Uint64(commit[0:8])
			if srvEpoch != d.Epoch {
				return fmt.Errorf("Document with invalid Epoch in SharedRandomCommit")
			}
		} else {
			return fmt.Errorf("Document has invalid SharedRandomCommit")
		}
		// Votes and Certificates or Consensus differ in that a Consensus has a SharedRandomValue and the set of SharedRandomCommit and SharedRandomReveals that produced it; otherwise there must be only one SharedRandomCommit, and no SharedRandomReveal
		switch len(d.SharedRandomCommit) {
		case 1:
			// This Document is a Vote and must have only one SharedRandomCommit
			// and no SharedRandomReveal
			// Vote and have only one SharedRandomCommit
			if len(d.SharedRandomReveal) != 0 {
				return fmt.Errorf("Document is not a valid Vote")
			}
		default:
			// verify each reveal
			if len(d.SharedRandomReveal) != len(d.SharedRandomCommit) {
				return fmt.Errorf("Document is Malformed")
			}
			signedReveal, ok := d.SharedRandomReveal[id]
			if !ok {
				return fmt.Errorf("Document is missing a SharedRandomReveal for %x", id)
			}
			// Verify the reveal
			reveal, err := cert.Verify(verifier, signedReveal)
			if err != nil {
				return fmt.Errorf("Document has an Invalid Signature on SharedRandomReveal for %x", id)
			}

			// Verify the commit with reveal
			srv := new(SharedRandom)
			srv.SetCommit(commit)
			if !srv.Verify(reveal) {
				return fmt.Errorf("Document has an invalid Reveal for! %x", id)
			}
		}
	}
	if len(d.Topology) == 0 {
		return fmt.Errorf("Document contains no Topology")
	}
	pks := make(map[[hash.HashSize]byte]bool)
	for layer, nodes := range d.Topology {
		if len(nodes) == 0 {
			return fmt.Errorf("Document Topology layer %d contains no nodes", layer)
		}
		for _, desc := range nodes {
			if err := IsDescriptorWellFormed(desc, d.Epoch); err != nil {
				return err
			}
			pk := hash.Sum256(desc.IdentityKey)
			if _, ok := pks[pk]; ok {
				return fmt.Errorf("Document contains multiple entries for %v", desc.IdentityKey)
			}
			pks[pk] = true
		}
	}
	if len(d.GatewayNodes) == 0 {
		return fmt.Errorf("Document contains no Gateway Nodes")
	}
	if len(d.ServiceNodes) == 0 {
		return fmt.Errorf("Document contains no Service Nodes")
	}

	for _, desc := range d.GatewayNodes {
		if err := IsDescriptorWellFormed(desc, d.Epoch); err != nil {
			return err
		}
		if !desc.IsGatewayNode {
			return fmt.Errorf("Document lists %v as a Provider with desc.IsGatewayNode = %v", desc.IdentityKey, desc.IsGatewayNode)
		}
		pk := hash.Sum256(desc.IdentityKey)
		if _, ok := pks[pk]; ok {
			return fmt.Errorf("Document contains multiple entries for %v", desc.IdentityKey)
		}
		pks[pk] = true
	}

	for _, desc := range d.ServiceNodes {
		if err := IsDescriptorWellFormed(desc, d.Epoch); err != nil {
			return err
		}
		if !desc.IsServiceNode {
			return fmt.Errorf("Document lists %v as a Provider with desc.IsServiceNode = %v", desc.IdentityKey, desc.IsServiceNode)
		}
		pk := hash.Sum256(desc.IdentityKey)
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
	d.Version = DocumentVersion
	payload, err := ccbor.Marshal((*document)(d))
	if err != nil {
		return nil, err
	}
	certified := cert.Certificate{
		Version:    cert.CertVersion,
		Expiration: d.Epoch + 5,
		KeyType:    d.PKISignatureScheme,
		Certified:  payload,
		Signatures: d.Signatures,
	}
	return certified.Marshal()
}

// UnmarshalBinary implements encoding.BinaryUnmarshaler interface
// and populates Document with detached Signatures
func (d *Document) UnmarshalBinary(data []byte) error {
	d.Signatures = make(map[[PublicKeyHashSize]byte]cert.Signature)
	certified, err := cert.GetCertified(data)
	if err != nil {
		return err
	}
	sigs, err := cert.GetSignatures(data)
	if err != nil {
		return err
	}
	if len(sigs) == 0 {
		return ErrDocumentNotSigned
	}
	for _, s := range sigs {
		d.Signatures[s.PublicKeySum256] = s
	}
	err = cbor.Unmarshal(certified, (*document)(d))
	if err != nil {
		return err
	}
	return nil
}

// AddSignature will add a Signature over this Document if it is signed by verifier.
func (d *Document) AddSignature(verifier sign.PublicKey, signature cert.Signature) error {
	// Serialize this Document
	payload, err := d.MarshalBinary()
	if err != nil {
		return err
	}

	// if AddSignature succeeds, add the Signature to d.Signatures
	_, err = cert.AddSignature(verifier, signature, payload)
	if err != nil {
		return err
	}
	d.Signatures[hash.Sum256From(verifier)] = signature
	return nil
}

func (d *Document) Sum256() [32]byte {
	b, err := d.MarshalBinary()
	if err != nil {
		panic(err)
	}
	return blake2b.Sum256(b)
}

func init() {
	var err error
	opts := cbor.CanonicalEncOptions()
	ccbor, err = opts.EncMode()
	if err != nil {
		panic(err)
	}
}

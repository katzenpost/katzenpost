// document.go - Katzenpost Non-voting authority document s11n.
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

package s11n

import (
	"errors"
	"fmt"
	"io"

	"golang.org/x/crypto/sha3"
	"github.com/katzenpost/authority/voting/server/config"
	"github.com/katzenpost/core/crypto/eddsa"
	"github.com/katzenpost/core/crypto/rand"
	"github.com/katzenpost/core/pki"
	"github.com/ugorji/go/codec"
	"gopkg.in/square/go-jose.v2"
)

const documentVersion = "voting-document-v0"

var (
	// ErrInvalidEpoch is the error to return when the document epoch is
	// invalid.
	ErrInvalidEpoch = errors.New("voting: invalid document epoch")

	jsonHandle *codec.JsonHandle
)

// Document is the on-the-wire representation of a PKI Document.
type Document struct {
	// Version uniquely identifies the document format as being for the
	// voting authority so that it can be rejected when unexpectedly
	// received or if the version changes.
	Version string

	Epoch uint64

	MixLambda   float64
	MixMaxDelay uint64

	SendLambda      float64
	SendShift       uint64
	SendMaxInterval uint64

	Topology  [][][]byte
	Providers [][]byte
	SRVCommit []byte
}

func FromPayload(verificationKey interface{}, payload []byte) (*Document, error) {
	signed, err := jose.ParseSigned(string(payload))
	if err != nil {
		return nil, err
	}
	_, _, verified, err := signed.VerifyMulti(verificationKey)
	if err != nil {
		return nil, err
	}
	dec := codec.NewDecoderBytes(verified, jsonHandle)
	d := new(Document)
	if err := dec.Decode(d); err != nil {
		return nil, err
	}
	return d, nil
}

// SignDocument signs and serializes the document with the provided signing key.
func SignDocument(signingKey *eddsa.PrivateKey, d *Document) (string, error) {
	d.Version = documentVersion

	// Serialize the document.
	var payload []byte
	enc := codec.NewEncoderBytes(&payload, jsonHandle)
	if err := enc.Encode(d); err != nil {
		return "", err
	}

	// Sign the document.
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

// ShinyMultiSignDocument signs and serializes the document with the provided signing key.
func MultiSignTestDocument(signingKeys []*eddsa.PrivateKey, d *Document) (string, error) {
	d.Version = documentVersion
	// Serialize the document.
	var payload []byte
	enc := codec.NewEncoderBytes(&payload, jsonHandle)
	if err := enc.Encode(d); err != nil {
		return "", err
	}
	keySet := []jose.SigningKey{}
	for _, key := range signingKeys {
		k := jose.SigningKey{
			Algorithm: jose.EdDSA,
			Key:       *key.InternalPtr(),
		}
		keySet = append(keySet, k)
	}
	// Sign the document.
	signer, err := jose.NewMultiSigner(keySet, nil)
	if err != nil {
		return "", err
	}
	signed, err := signer.Sign(payload)
	if err != nil {
		return "", err
	}
	// Serialize the key, descriptor and signature.
	return signed.FullSerialize(), nil
}

// SignDocument signs and serializes the document with the provided signing key.
func MultiSignDocument(signingKey *eddsa.PrivateKey, peerSignatures map[[eddsa.PublicKeySize]byte]*jose.Signature, d *Document) (string, error) {
	d.Version = documentVersion

	// Serialize the document.
	var payload []byte
	enc := codec.NewEncoderBytes(&payload, jsonHandle)
	if err := enc.Encode(d); err != nil {
		return "", err
	}

	// Sign the document.
	k := jose.SigningKey{
		Algorithm: jose.EdDSA,
		Key:       *signingKey.InternalPtr(),
	}
	signer, err := jose.NewMultiSigner([]jose.SigningKey{k}, nil) // XXX multiple signing keys
	if err != nil {
		return "", err
	}
	signed, err := signer.Sign(payload)
	if err != nil {
		return "", err
	}

	// attach peer signatures
	if peerSignatures != nil {
		for _, sig := range peerSignatures {
			signed.Signatures = append(signed.Signatures, *sig)
		}
	}

	// Serialize the key, descriptor and signature.
	return signed.FullSerialize(), nil
}

// VerifyPeerMulti returns a map of keys to signatures for
// the peer keys that produced a valid signature
func VerifyPeerMulti(payload []byte, peers []*config.AuthorityPeer) (map[[eddsa.PublicKeySize]byte]*jose.Signature, error) {
	signed, err := jose.ParseSigned(string(payload))
	if err != nil {
		return nil, fmt.Errorf("VerifyPeerMulti failure: %s", err)
	}
	sigMap := make(map[[eddsa.PublicKeySize]byte]*jose.Signature)
	for _, peer := range peers {
		_, signature, _, err := signed.VerifyMulti(*peer.IdentityPublicKey.InternalPtr())
		if err == nil {
			sigMap[peer.IdentityPublicKey.ByteArray()] = &signature
		}
	}
	return sigMap, nil
}

// VerifyAndParseDocument verifies the signautre and deserializes the document.
func VerifyAndParseDocument(b []byte, publicKey *eddsa.PublicKey) (*pki.Document, []byte, error) {
	signed, err := jose.ParseSigned(string(b))
	if err != nil {
		return nil, nil, fmt.Errorf("authority: jose.ParseSigned failed: %s", err)
	}

	// XXX shouldn't the library do this for us?
	for _, sig := range signed.Signatures {
		alg := sig.Header.Algorithm
		if alg != "EdDSA" {
			return nil, nil, fmt.Errorf("authority: Unsupported signature algorithm: '%v'", alg)
		}
	}

	_, _, payload, err := signed.VerifyMulti(*publicKey.InternalPtr())
	if err != nil {
		if err == jose.ErrCryptoFailure {
			err = fmt.Errorf("authority: Invalid document signature")
		}
		return nil, nil, err
	}

	// Parse the payload.
	d := new(Document)
	dec := codec.NewDecoderBytes(payload, jsonHandle)
	if err = dec.Decode(d); err != nil {
		return nil, nil, err
	}

	// Ensure the document is well formed.
	if d.Version != documentVersion {
		return nil, nil, fmt.Errorf("authority: Invalid Document Version: '%v'", d.Version)
	}

	// Convert from the wire representation to a Document, and validate
	// everything.
	if len(d.SRVCommit) != 40 {
		return nil, nil, fmt.Errorf("authority: Recived a vote with invalid or missing SRV Commit"
	}

	// Ensure that the document contains a SRV Commit value, and that
	// the Epoch prefix corresponds to the current Epoch.
	srvEpoch := binary.BigEndian.Uint64(d.SRVCommit[0:8])
	if srvEpoch != d.Epoch {
		return nil, nil, fmt.Errorf("authority: Recived a vote with invalid or missing SRV Commit"

	}
	doc := new(pki.Document)
	doc.SRVCommit = make([]byte, 40)
	copy(d.SRVCommit, doc.SRVCommit)
	doc.Epoch = d.Epoch
	doc.MixLambda = d.MixLambda
	doc.MixMaxDelay = d.MixMaxDelay
	doc.SendLambda = d.SendLambda
	doc.SendShift = d.SendShift
	doc.SendMaxInterval = d.SendMaxInterval
	doc.Topology = make([][]*pki.MixDescriptor, len(d.Topology))
	doc.Providers = make([]*pki.MixDescriptor, 0, len(d.Providers))

	for layer, nodes := range d.Topology {
		for _, rawDesc := range nodes {
			desc, err := VerifyAndParseDescriptor(rawDesc, doc.Epoch)
			if err != nil {
				return nil, nil, err
			}
			doc.Topology[layer] = append(doc.Topology[layer], desc)
		}
	}

	for _, rawDesc := range d.Providers {
		desc, err := VerifyAndParseDescriptor(rawDesc, doc.Epoch)
		if err != nil {
			return nil, nil, fmt.Errorf("VerifyAndParseDocument fail: VerifyAndParseDescriptor failure: %s", err)
		}
		doc.Providers = append(doc.Providers, desc)
	}

	if err = IsDocumentWellFormed(doc); err != nil {
		return nil, nil, fmt.Errorf("VerifyAndParseDocument IsDocumentWellFormed failure:  %s", err)
	}

	// Fixup the Layer field in all the Topology MixDescriptors.
	for layer, nodes := range doc.Topology {
		for _, desc := range nodes {
			desc.Layer = uint8(layer)
		}
	}

	return doc, payload, nil
}

// IsDocumentWellFormed validates the document and returns a descriptive error
// iff there are any problems that invalidates the document.
func IsDocumentWellFormed(d *pki.Document) error {
	pks := make(map[[eddsa.PublicKeySize]byte]bool)
	if len(d.Topology) == 0 {
		return fmt.Errorf("voting: Document contains no Topology")
	}
	for layer, nodes := range d.Topology {
		if len(nodes) == 0 {
			return fmt.Errorf("voting: Document Topology layer %d contains no nodes", layer)
		}
		for _, desc := range nodes {
			if err := IsDescriptorWellFormed(desc, d.Epoch); err != nil {
				return err
			}
			pk := desc.IdentityKey.ByteArray()
			if _, ok := pks[pk]; ok {
				return fmt.Errorf("voting: Document contains multiple entries for %v", desc.IdentityKey)
			}
			pks[pk] = true
		}
	}
	if len(d.Providers) == 0 {
		return fmt.Errorf("voting: Document contains no Providers")
	}
	for _, desc := range d.Providers {
		if err := IsDescriptorWellFormed(desc, d.Epoch); err != nil {
			return err
		}
		if desc.Layer != pki.LayerProvider {
			return fmt.Errorf("voting: Document lists %v as a Provider with layer %v", desc.IdentityKey, desc.Layer)
		}
		pk := desc.IdentityKey.ByteArray()
		if _, ok := pks[pk]; ok {
			return fmt.Errorf("voting: Document contains multiple entries for %v", desc.IdentityKey)
		}
		pks[pk] = true
	}

	return nil
}

func init() {
	jsonHandle = new(codec.JsonHandle)
	jsonHandle.Canonical = true
	jsonHandle.IntegerAsString = 'A'
	jsonHandle.MapKeyAsString = true
}

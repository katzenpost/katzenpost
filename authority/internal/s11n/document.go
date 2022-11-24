// document.go - Katzenpost authority document s11n.
// Copyright (C) 2017, 2018  Yawning Angel, masala, David Stainton
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
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/katzenpost/katzenpost/core/crypto/cert"
	"github.com/katzenpost/katzenpost/core/crypto/sign"
	"github.com/katzenpost/katzenpost/core/pki"
	"github.com/ugorji/go/codec"
)

const (
	// DocumentVersion is the string identifying the format of the Document
	DocumentVersion = "document-v0"
	// SharedRandomLength is the length in bytes of a SharedRandomCommit.
	SharedRandomLength = 40
	// SharedRandomValueLength is the length in bytes of a SharedRandomValue.
	SharedRandomValueLength = 32
)

var (
	// ErrInvalidEpoch is the error to return when the document epoch is
	// invalid.
	ErrInvalidEpoch = errors.New("invalid document epoch")

	jsonHandle *codec.JsonHandle
)

// FromPayload deserializes, then verifies a Document, and returns the Document or error.
func FromPayload(verifier cert.Verifier, payload []byte) (*pki.Document, error) {
	verified, err := cert.Verify(verifier, payload)
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
func SignDocument(signer cert.Signer, verifier cert.Verifier, d *pki.Document) ([]byte, error) {
	d.Version = DocumentVersion

	// Serialize the document.
	var payload []byte
	enc := codec.NewEncoderBytes(&payload, jsonHandle)
	if err := enc.Encode(d); err != nil {
		return nil, err
	}

	// Sign the document.
	return cert.Sign(signer, verifier, payload, d.Epoch+4)
}

// MultiSignDocument signs and serializes the document with the provided signing key, adding the signature to the existing signatures.
func MultiSignDocument(signer cert.Signer, verifier cert.Verifier, peerSignatures []*cert.Signature, verifiers map[[32]byte]cert.Verifier, d *pki.Document) ([]byte, error) {
	d.Version = DocumentVersion

	// Serialize the document.
	var payload []byte
	enc := codec.NewEncoderBytes(&payload, jsonHandle)
	if err := enc.Encode(d); err != nil {
		return nil, err
	}

	// Sign the document.
	signed, err := cert.Sign(signer, verifier, payload, d.Epoch+4)
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
func VerifyAndParseDocument(b []byte, verifier cert.Verifier) (*pki.Document, error) {
	payload, err := cert.Verify(verifier, b)
	if err != nil {
		return nil, err
	}

	// Parse the payload.
	d := new(pki.Document)
	dec := codec.NewDecoderBytes(payload, jsonHandle)
	if err = dec.Decode(d); err != nil {
		return nil, err
	}

	// Ensure the document is well formed.
	if d.Version != DocumentVersion {
		return nil, fmt.Errorf("Invalid Document Version: '%v'", d.Version)
	}

	// Convert from the wire representation to a Document, and validate
	// everything.

	// If there is a SharedRandomCommit, verify the Epoch contained in SharedRandomCommit matches the Epoch in the Document.
	if len(d.SharedRandomCommit) == SharedRandomLength {
		srvEpoch := binary.BigEndian.Uint64(d.SharedRandomCommit[0:8])
		if srvEpoch != d.Epoch {
			return nil, fmt.Errorf("Document with invalid Epoch in SharedRandomCommit")

		}
	}
	if len(d.SharedRandomValue) != SharedRandomValueLength {
		if len(d.SharedRandomValue) != 0 {
			return nil, fmt.Errorf("Document has invalid SharedRandomValue")
		} else if len(d.SharedRandomCommit) != SharedRandomLength {
			return nil, fmt.Errorf("Document has invalid SharedRandomCommit")
		}
	}
	if len(d.SharedRandomCommit) != SharedRandomLength {
		if len(d.SharedRandomCommit) != 0 {
			return nil, fmt.Errorf("Document has invalid SharedRandomCommit")
		} else if len(d.SharedRandomValue) != SharedRandomValueLength {
			return nil, fmt.Errorf("Document has invalid SharedRandomValue")
		}
	}
	if d.GenesisEpoch == 0 {
		return nil, fmt.Errorf("Document has invalid GenesisEpoch")
	}
	if len(d.PriorSharedRandom) == 0 && d.GenesisEpoch != d.Epoch {
		return nil, fmt.Errorf("Document has invalid PriorSharedRandom")
	}

	// XXX: this desrialization stuff needs to live in pki.MixDescriptor and impl. BinaryMarshaller.
	for layer, nodes := range d.Topology {
		for _, rawDesc := range nodes {
			verifier, err := GetVerifierFromDescriptor(rawDesc)
			if err != nil {
				return nil, err
			}
			desc, err := VerifyAndParseDescriptor(verifier, rawDesc, doc.Epoch)
			if err != nil {
				return nil, err
			}
			doc.Topology[layer] = append(doc.Topology[layer], desc)
		}
	}

	for _, rawDesc := range d.Providers {
		verifier, err := GetVerifierFromDescriptor(rawDesc)
		if err != nil {
			return nil, err
		}
		desc, err := VerifyAndParseDescriptor(verifier, rawDesc, doc.Epoch)
		if err != nil {
			return nil, err
		}
		doc.Providers = append(doc.Providers, desc)
	}

	if err = IsDocumentWellFormed(doc); err != nil {
		return nil, err
	}

	// Fixup the Layer field in all the Topology MixDescriptors.
	for layer, nodes := range doc.Topology {
		for _, desc := range nodes {
			desc.Layer = uint8(layer) // omg?
		}
	}

	return doc, nil
}

// IsDocumentWellFormed validates the document and returns a descriptive error
// iff there are any problems that invalidates the document.
// XXX: this should also live in core/pki
func IsDocumentWellFormed(d *pki.Document) error {
	pks := make(map[[sign.PublicKeyHashSize]byte]bool)
	if len(d.Topology) == 0 {
		return fmt.Errorf("Document contains no Topology")
	}
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
		if desc.Layer != pki.LayerProvider {
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

func init() {
	jsonHandle = new(codec.JsonHandle)
	jsonHandle.Canonical = true
	jsonHandle.IntegerAsString = 'A'
	jsonHandle.MapKeyAsString = true
}

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
	"time"

	"github.com/katzenpost/core/crypto/cert"
	"github.com/katzenpost/core/epochtime"
	"github.com/katzenpost/core/pki"
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

// Document is the on-the-wire representation of a PKI Document.
type Document struct {
	// Version uniquely identifies the document format as being for the
	// specified version so that it can be rejected if the format changes.
	Version           string
	Epoch             uint64
	SendRatePerMinute uint64

	Mu              float64
	MuMaxDelay      uint64
	LambdaP         float64
	LambdaPMaxDelay uint64
	LambdaL         float64
	LambdaLMaxDelay uint64
	LambdaD         float64
	LambdaDMaxDelay uint64
	LambdaM         float64
	LambdaMMaxDelay uint64

	Topology  [][][]byte
	Providers [][]byte

	SharedRandomCommit []byte
	SharedRandomValue  []byte
}

// FromPayload deserializes, then verifies a Document, and returns the Document or error.
func FromPayload(verifier cert.Verifier, payload []byte) (*Document, error) {
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
func SignDocument(signer cert.Signer, d *Document) ([]byte, error) {
	d.Version = DocumentVersion

	// Serialize the document.
	var payload []byte
	enc := codec.NewEncoderBytes(&payload, jsonHandle)
	if err := enc.Encode(d); err != nil {
		return nil, err
	}

	// Sign the document.
	expiration := time.Now().Add(CertificateExpiration).Unix()
	return cert.Sign(signer, payload, expiration)
}

// MultiSignDocument signs and serializes the document with the provided signing key, adding the signature to the existing signatures.
func MultiSignDocument(signer cert.Signer, peerSignatures []*cert.Signature, verifiers map[string]cert.Verifier, d *Document) ([]byte, error) {
	d.Version = DocumentVersion

	// Serialize the document.
	var payload []byte
	enc := codec.NewEncoderBytes(&payload, jsonHandle)
	if err := enc.Encode(d); err != nil {
		return nil, err
	}

	// Sign the document.
	expiration := time.Now().Add(3 * epochtime.Period).Unix()
	signed, err := cert.Sign(signer, payload, expiration)
	if err != nil {
		return nil, err
	}

	// attach peer signatures
	for _, signature := range peerSignatures {
		s := string(signature.Identity)
		verifier := verifiers[s]
		signed, err = cert.AddSignature(verifier, *signature, signed)
		if err != nil {
			return nil, err
		}
	}

	return signed, nil
}

// VerifyAndParseDocument verifies the signautre and deserializes the document.
func VerifyAndParseDocument(b []byte, verifier cert.Verifier) (*pki.Document, error) {
	payload, err := cert.Verify(verifier, b)
	if err != nil {
		return nil, err
	}

	// Parse the payload.
	d := new(Document)
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

	doc := new(pki.Document)
	doc.SharedRandomCommit = d.SharedRandomCommit
	doc.SharedRandomValue = d.SharedRandomValue
	doc.Epoch = d.Epoch
	doc.SendRatePerMinute = d.SendRatePerMinute
	doc.Mu = d.Mu
	doc.MuMaxDelay = d.MuMaxDelay
	doc.LambdaP = d.LambdaP
	doc.LambdaPMaxDelay = d.LambdaPMaxDelay
	doc.LambdaL = d.LambdaL
	doc.LambdaLMaxDelay = d.LambdaLMaxDelay
	doc.LambdaD = d.LambdaD
	doc.LambdaDMaxDelay = d.LambdaDMaxDelay
	doc.LambdaM = d.LambdaM
	doc.LambdaMMaxDelay = d.LambdaMMaxDelay
	doc.Topology = make([][]*pki.MixDescriptor, len(d.Topology))
	doc.Providers = make([]*pki.MixDescriptor, 0, len(d.Providers))

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
			desc.Layer = uint8(layer)
		}
	}

	return doc, nil
}

// IsDocumentWellFormed validates the document and returns a descriptive error
// iff there are any problems that invalidates the document.
func IsDocumentWellFormed(d *pki.Document) error {
	pks := make(map[string]bool)
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
			pk := string(desc.IdentityKey.Identity())
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
		pk := string(desc.IdentityKey.Identity())
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

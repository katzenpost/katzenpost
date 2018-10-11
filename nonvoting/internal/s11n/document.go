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
	"time"

	"github.com/katzenpost/core/crypto/cert"
	"github.com/katzenpost/core/pki"
	"github.com/ugorji/go/codec"
)

const documentVersion = "nonvoting-document-v0"

var (
	// ErrInvalidEpoch is the error to return when the document epoch is
	// invalid.
	ErrInvalidEpoch = errors.New("nonvoting: invalid document epoch")

	jsonHandle *codec.JsonHandle
)

// Document is the on-the-wire representation of a PKI Document.
type Document struct {
	// Version uniquely identifies the document format as being for the
	// non-voting authority so that it can be rejected when unexpectedly
	// received or if the version changes.
	Version string

	Epoch uint64

	MixLambda   float64
	MixMaxDelay uint64

	SendLambda      float64
	SendShift       uint64
	SendMaxInterval uint64
	DropLambda      float64
	DropShift       uint64
	DropMaxInterval uint64
	LoopLambda      float64
	LoopShift       uint64
	LoopMaxInterval uint64

	Topology  [][][]byte
	Providers [][]byte
}

// SignDocument signs and serializes the document with the provided signing key.
func SignDocument(signer cert.Signer, d *Document) ([]byte, error) {
	d.Version = documentVersion

	// Serialize the document.
	var payload []byte
	enc := codec.NewEncoderBytes(&payload, jsonHandle)
	if err := enc.Encode(d); err != nil {
		return nil, err
	}

	// Sign the document.
	expiration := time.Now().Add(certificateExpiration).Unix()
	return cert.Sign(signer, payload, expiration)
}

// VerifyAndParseDocument verifies the signautre and deserializes the document.
func VerifyAndParseDocument(b []byte, verifier cert.Verifier) (*pki.Document, error) {
	// Sanity check the number of signatures, and
	// validate the signature with the provided public key.
	signatures, err := cert.GetSignatures(b)
	if len(signatures) != 1 {
		return nil, fmt.Errorf("nonvoting: Expected 1 signature, got: %v", len(signatures))
	}
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
	if d.Version != documentVersion {
		return nil, fmt.Errorf("nonvoting: Invalid Document Version: '%v'", d.Version)
	}

	// Convert from the wire representation to a Document, and validate
	// everything.
	doc := new(pki.Document)
	doc.Epoch = d.Epoch
	doc.MixLambda = d.MixLambda
	doc.MixMaxDelay = d.MixMaxDelay
	doc.SendLambda = d.SendLambda
	doc.SendShift = d.SendShift
	doc.SendMaxInterval = d.SendMaxInterval
	doc.DropLambda = d.DropLambda
	doc.DropShift = d.DropShift
	doc.DropMaxInterval = d.DropMaxInterval
	doc.LoopLambda = d.LoopLambda
	doc.LoopShift = d.LoopShift
	doc.LoopMaxInterval = d.LoopMaxInterval
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
		return fmt.Errorf("nonvoting: Document contains no Topology")
	}
	for layer, nodes := range d.Topology {
		if len(nodes) == 0 {
			return fmt.Errorf("nonvoting: Document Topology layer %d contains no nodes", layer)
		}
		for _, desc := range nodes {
			if err := IsDescriptorWellFormed(desc, d.Epoch); err != nil {
				return err
			}
			pk := string(desc.IdentityKey.Identity())
			if _, ok := pks[pk]; ok {
				return fmt.Errorf("nonvoting: Document contains multiple entries for %v", desc.IdentityKey)
			}
			pks[pk] = true
		}
	}
	if len(d.Providers) == 0 {
		return fmt.Errorf("nonvoting: Document contains no Providers")
	}
	for _, desc := range d.Providers {
		if err := IsDescriptorWellFormed(desc, d.Epoch); err != nil {
			return err
		}
		if desc.Layer != pki.LayerProvider {
			return fmt.Errorf("nonvoting: Document lists %v as a Provider with layer %v", desc.IdentityKey, desc.Layer)
		}
		pk := string(desc.IdentityKey.Identity())
		if _, ok := pks[pk]; ok {
			return fmt.Errorf("nonvoting: Document contains multiple entries for %v", desc.IdentityKey)
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

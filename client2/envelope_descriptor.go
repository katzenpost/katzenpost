// SPDX-FileCopyrightText: © 2025 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package client2

import (
	"fmt"

	"github.com/fxamacker/cbor/v2"

	"github.com/katzenpost/hpqc/hash"
	hpqcRand "github.com/katzenpost/hpqc/rand"

	"github.com/katzenpost/katzenpost/client2/common"
	"github.com/katzenpost/katzenpost/client2/constants"
	cpki "github.com/katzenpost/katzenpost/core/pki"
)

const (
	// Error message for missing connection
	errNoConnectionForAppID = "no connection associated with AppID %x"
)

var (
	// Package-level cryptographically secure random number generator
	secureRand = hpqcRand.NewMath()
)

// EnvelopeDescriptor supplies us with everthing we need to decrypt
// an encrypted envelope reply from a storage replica via the courier.
// The assumption is that we have access to the PKI document for the
// Epoch in which the envelope was sent.
type EnvelopeDescriptor struct {
	// Epoch is the Katzenpost epoch in which the ReplyIndex is valid.
	Epoch uint64

	// ReplicaNums are the replica numbers used for this envelope.
	ReplicaNums [2]uint8

	// EnvelopeKey is the Private NIKE Key used with our MKEM scheme.
	EnvelopeKey []byte
}

// Bytes uses CBOR to serialize the EnvelopeDescriptor.
func (e *EnvelopeDescriptor) Bytes() ([]byte, error) {
	blob, err := cbor.Marshal(e)
	if err != nil {
		return nil, err
	}
	return blob, nil
}

// EnvelopeDescriptorFromBytes uses CBOR to deserialize the EnvelopeDescriptor.
func EnvelopeDescriptorFromBytes(blob []byte) (*EnvelopeDescriptor, error) {
	var desc EnvelopeDescriptor
	err := cbor.Unmarshal(blob, &desc)
	if err != nil {
		return nil, err
	}
	return &desc, nil
}

func GetRandomCourier(doc *cpki.Document) (*[hash.HashSize]byte, []byte, error) {
	courierServices := common.FindServices(constants.CourierServiceName, doc)
	if len(courierServices) == 0 {
		return nil, nil, fmt.Errorf("no courier services found in PKI document")
	}
	courierService := courierServices[secureRand.Intn(len(courierServices))]
	serviceIdHash := hash.Sum256(courierService.MixDescriptor.IdentityKey)
	return &serviceIdHash, courierService.RecipientQueueID, nil
}

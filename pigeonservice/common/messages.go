// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package common

import (
	"errors"
	"fmt"

	"github.com/fxamacker/cbor/v2"

	"github.com/katzenpost/hpqc/hash"
)

const (
	// ParamNIKEScheme and ParamPublicKey are the keys under which the
	// router and the directory publish their NIKE public key in the PKI.
	ParamNIKEScheme = "nikeScheme"
	ParamPublicKey  = "publicKey"
)

// Reply status codes shared by the router and the directory.
const (
	StatusOK uint8 = iota
	StatusInvalidRequest
	StatusBadMAC
	StatusUnknownService
	StatusStale
	StatusBusy
	StatusInternalError
)

// StatusError is a non-OK status from a router or a directory.
type StatusError struct {
	Status uint8
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("pigeonservice: status %d", e.Status)
}

// ServiceID names a service: the BLAKE2b-256 hash of its public key.
type ServiceID [32]byte

// IDFromPublicKey returns the ServiceID of a public key.
func IDFromPublicKey(publicKey []byte) ServiceID {
	return ServiceID(hash.Sum256(publicKey))
}

// RouterRef names one voucher router: the service node it runs on and its
// endpoint there.
type RouterRef struct {
	NodeIDHash [32]byte
	Endpoint   string
}

// ServiceDescriptor is everything a client needs to reach a service.
type ServiceDescriptor struct {
	// NIKEScheme names the scheme of PublicKey.
	NIKEScheme string
	// PublicKey is the key a client seals its voucher to.
	PublicKey []byte
	// Routers are the voucher routers holding a live link with the service.
	Routers []RouterRef
}

// ID returns the descriptor's ServiceID.
func (d *ServiceDescriptor) ID() ServiceID {
	return IDFromPublicKey(d.PublicKey)
}

var ccbor cbor.EncMode

func init() {
	var err error
	ccbor, err = cbor.CanonicalEncOptions().EncMode()
	if err != nil {
		panic(err)
	}
}

// Marshal encodes v as canonical CBOR.
func Marshal(v any) ([]byte, error) {
	return ccbor.Marshal(v)
}

// ErrTrailingData reports bytes after a CBOR item that are not padding.
var ErrTrailingData = errors.New("pigeonservice: trailing data after CBOR")

// Unmarshal decodes one CBOR item into v. Sphinx payloads arrive padded to
// their full length, so trailing zero bytes are accepted; anything else
// after the item is an error.
func Unmarshal(b []byte, v any) error {
	rest, err := cbor.UnmarshalFirst(b, v)
	if err != nil {
		return err
	}
	for _, c := range rest {
		if c != 0 {
			return ErrTrailingData
		}
	}
	return nil
}

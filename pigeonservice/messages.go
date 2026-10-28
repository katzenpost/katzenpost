// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package pigeonservice

import (
	"github.com/fxamacker/cbor/v2"

	"github.com/katzenpost/hpqc/hash"
)

const (
	// RouterCapability is the kaetzchen capability of the voucher router.
	RouterCapability = "voucher_router"

	// DirectoryCapability is the kaetzchen capability of the service directory.
	DirectoryCapability = "service_directory"

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

// RouterRequest is the payload of a Sphinx query to a voucher router.
// Exactly one field is set.
type RouterRequest struct {
	Route    *RouteRequest    `cbor:",omitempty"`
	Register *RegisterRequest `cbor:",omitempty"`
}

// RouteRequest asks a router to forward a sealed voucher to a service.
type RouteRequest struct {
	ServiceID  ServiceID
	Ciphertext []byte
}

// RegisterRequest asks a router to open a link with a service. Voucher is a
// contact voucher the service minted for its service→router stream; the
// router inducts it and so gives the service its router→service stream.
type RegisterRequest struct {
	NIKEScheme string
	PublicKey  []byte
	Voucher    []byte
	MAC        []byte
}

// RouterReply is the router's answer to a RouterRequest.
type RouterReply struct {
	Status uint8
}

// LinkMessage is one box on a router→service link.
type LinkMessage struct {
	// Forward is a client's sealed voucher.
	Forward []byte `cbor:",omitempty"`
}

// DirectoryRequest is the payload of a Sphinx query to the service
// directory. Exactly one field is set.
type DirectoryRequest struct {
	Advertise *AdvertiseRequest `cbor:",omitempty"`
	Withdraw  *WithdrawRequest  `cbor:",omitempty"`
	Lookup    *LookupRequest    `cbor:",omitempty"`
	List      *ListRequest      `cbor:",omitempty"`
}

// AdvertiseRequest publishes or replaces a service's descriptor. Seq must
// exceed the Seq of the descriptor it replaces.
type AdvertiseRequest struct {
	Descriptor ServiceDescriptor
	Seq        uint64
	MAC        []byte
}

// WithdrawRequest removes a service's descriptor. Seq must exceed the Seq of
// the descriptor it removes.
type WithdrawRequest struct {
	ServiceID ServiceID
	Seq       uint64
	MAC       []byte
}

// LookupRequest asks for one service's descriptor.
type LookupRequest struct {
	ServiceID ServiceID
}

// ListRequest asks where the current snapshot of all descriptors is.
type ListRequest struct{}

// DirectoryReply is the directory's answer to a DirectoryRequest.
type DirectoryReply struct {
	Status uint8
	// Descriptor answers a Lookup.
	Descriptor *ServiceDescriptor `cbor:",omitempty"`
	// ReadCap and StartIndex locate the snapshot stream, answering a List.
	ReadCap    []byte `cbor:",omitempty"`
	StartIndex []byte `cbor:",omitempty"`
}

// Snapshot is the content of a snapshot stream: every descriptor the
// directory holds.
type Snapshot struct {
	Seq         uint64
	Descriptors []ServiceDescriptor
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

// Unmarshal decodes CBOR into v.
func Unmarshal(b []byte, v any) error {
	return cbor.Unmarshal(b, v)
}

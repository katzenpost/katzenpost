// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package discovery

import (
	"github.com/katzenpost/hpqc/nike"

	"github.com/katzenpost/katzenpost/pigeonservice/common"
)

// DirectoryCapability is the kaetzchen capability of the service directory.
const DirectoryCapability = "service_directory"

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
	Descriptor common.ServiceDescriptor
	Seq        uint64
	MAC        []byte
}

// WithdrawRequest removes a service's descriptor. Seq must exceed the Seq of
// the descriptor it removes.
type WithdrawRequest struct {
	ServiceID common.ServiceID
	Seq       uint64
	MAC       []byte
}

// LookupRequest asks for one service's descriptor.
type LookupRequest struct {
	ServiceID common.ServiceID
}

// ListRequest asks where the current snapshot of all descriptors is.
type ListRequest struct{}

// DirectoryReply is the directory's answer to a DirectoryRequest.
type DirectoryReply struct {
	Status uint8
	// Descriptor answers a Lookup.
	Descriptor *common.ServiceDescriptor `cbor:",omitempty"`
	// ReadCap and StartIndex locate the snapshot stream, answering a List.
	ReadCap    []byte `cbor:",omitempty"`
	StartIndex []byte `cbor:",omitempty"`
}

// Snapshot is the content of a snapshot stream: every descriptor the
// directory holds.
type Snapshot struct {
	Seq         uint64
	Descriptors []common.ServiceDescriptor
}

// SignAdvertise fills in r.MAC for the directory whose public key is dirPub.
func SignAdvertise(k *common.ServiceKey, dirPub nike.PublicKey, r *AdvertiseRequest) error {
	r.MAC = nil
	mac, err := k.Sign(dirPub, r)
	r.MAC = mac
	return err
}

// VerifyAdvertise checks r.MAC against the descriptor's own public key.
func VerifyAdvertise(k *common.PluginKey, r *AdvertiseRequest) error {
	if r.Descriptor.NIKEScheme != k.Scheme.Name() {
		return common.ErrBadMAC
	}
	unsigned := *r
	unsigned.MAC = nil
	return k.Verify(r.Descriptor.PublicKey, &unsigned, r.MAC)
}

// SignWithdraw fills in r.MAC for the directory whose public key is dirPub.
func SignWithdraw(k *common.ServiceKey, dirPub nike.PublicKey, r *WithdrawRequest) error {
	r.MAC = nil
	mac, err := k.Sign(dirPub, r)
	r.MAC = mac
	return err
}

// VerifyWithdraw checks r.MAC against servicePub, the public key of the
// descriptor being withdrawn.
func VerifyWithdraw(k *common.PluginKey, servicePub []byte, r *WithdrawRequest) error {
	if common.IDFromPublicKey(servicePub) != r.ServiceID {
		return common.ErrBadMAC
	}
	unsigned := *r
	unsigned.MAC = nil
	return k.Verify(servicePub, &unsigned, r.MAC)
}

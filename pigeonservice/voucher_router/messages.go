// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package voucher_router

import (
	"github.com/katzenpost/hpqc/nike"

	"github.com/katzenpost/katzenpost/pigeonservice/common"
)

// RouterCapability is the kaetzchen capability of the voucher router.
const RouterCapability = "voucher_router"

// RouterRequest is the payload of a Sphinx query to a voucher router.
// Exactly one field is set.
type RouterRequest struct {
	Route    *RouteRequest    `cbor:",omitempty"`
	Register *RegisterRequest `cbor:",omitempty"`
}

// RouteRequest asks a router to forward a sealed voucher to a service.
type RouteRequest struct {
	ServiceID  common.ServiceID
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

// SignRegister fills in r.MAC for the router whose public key is routerPub.
func SignRegister(k *common.ServiceKey, routerPub nike.PublicKey, r *RegisterRequest) error {
	r.MAC = nil
	mac, err := k.Sign(routerPub, r)
	r.MAC = mac
	return err
}

// VerifyRegister checks r.MAC.
func VerifyRegister(k *common.PluginKey, r *RegisterRequest) error {
	if r.NIKEScheme != k.Scheme.Name() {
		return common.ErrBadMAC
	}
	unsigned := *r
	unsigned.MAC = nil
	return k.Verify(r.PublicKey, &unsigned, r.MAC)
}

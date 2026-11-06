// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package common

import (
	"crypto/hmac"
	"errors"
	"hash"
	"io"

	"golang.org/x/crypto/blake2b"
	"golang.org/x/crypto/hkdf"

	"github.com/katzenpost/hpqc/nike"
	"github.com/katzenpost/hpqc/util"
)

// Requests a service makes of a router or a directory carry a MAC under a
// key both sides derive from a NIKE exchange between the service's key and
// the plugin's key, which the plugin publishes in the PKI:
//
//	ss  = DH(servicePriv, pluginPub) = DH(pluginPriv, servicePub)
//	key = HKDF-BLAKE2b-256(ss, info = macLabel || pluginPub || servicePub)
//	mac = BLAKE2b-256(key = key, msg = canonical CBOR of the request with MAC unset)
//
// The plugin learns that the request came from the holder of the service's
// private key without a challenge round.

var macLabel = []byte("katzenpost-pigeonservice-mac-v1")

var (
	// ErrBadMAC reports a request MAC that does not verify.
	ErrBadMAC = errors.New("pigeonservice: bad MAC")
	// ErrDegenerateSharedSecret reports an all-zero NIKE shared secret.
	ErrDegenerateSharedSecret = errors.New("pigeonservice: degenerate shared secret")
)

func macKey(scheme nike.Scheme, priv nike.PrivateKey, peer nike.PublicKey, pluginPub, servicePub []byte) ([]byte, error) {
	ss := scheme.DeriveSecret(priv, peer)
	defer util.ExplicitBzero(ss)
	if len(ss) == 0 || util.CtIsZero(ss) {
		return nil, ErrDegenerateSharedSecret
	}
	info := make([]byte, 0, len(macLabel)+len(pluginPub)+len(servicePub))
	info = append(info, macLabel...)
	info = append(info, pluginPub...)
	info = append(info, servicePub...)
	newHash := func() hash.Hash { h, _ := blake2b.New256(nil); return h }
	key := make([]byte, 32)
	if _, err := io.ReadFull(hkdf.New(newHash, ss, nil, info), key); err != nil {
		return nil, err
	}
	return key, nil
}

func macOf(key []byte, v any) ([]byte, error) {
	body, err := Marshal(v)
	if err != nil {
		return nil, err
	}
	h, err := blake2b.New256(key)
	if err != nil {
		return nil, err
	}
	h.Write(body)
	return h.Sum(nil), nil
}

// ServiceKey is a service's NIKE keypair.
type ServiceKey struct {
	Scheme  nike.Scheme
	Public  nike.PublicKey
	Private nike.PrivateKey
}

// ID returns the service's ServiceID.
func (k *ServiceKey) ID() ServiceID {
	return IDFromPublicKey(k.Public.Bytes())
}

// Sign computes the MAC of request v as the service, for the plugin whose
// public key is pluginPub.
func (k *ServiceKey) Sign(pluginPub nike.PublicKey, v any) ([]byte, error) {
	key, err := macKey(k.Scheme, k.Private, pluginPub, pluginPub.Bytes(), k.Public.Bytes())
	if err != nil {
		return nil, err
	}
	defer util.ExplicitBzero(key)
	return macOf(key, v)
}

// PluginKey is a router's or a directory's NIKE keypair.
type PluginKey struct {
	Scheme  nike.Scheme
	Public  nike.PublicKey
	Private nike.PrivateKey
}

// Verify checks the MAC of request v as the plugin, for the service whose
// public key is servicePub.
func (k *PluginKey) Verify(servicePub []byte, v any, mac []byte) error {
	pub, err := k.Scheme.UnmarshalBinaryPublicKey(servicePub)
	if err != nil {
		return ErrBadMAC
	}
	key, err := macKey(k.Scheme, k.Private, pub, k.Public.Bytes(), servicePub)
	if err != nil {
		return ErrBadMAC
	}
	defer util.ExplicitBzero(key)
	want, err := macOf(key, v)
	if err != nil {
		return ErrBadMAC
	}
	if !hmac.Equal(want, mac) {
		return ErrBadMAC
	}
	return nil
}

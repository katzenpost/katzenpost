// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package pigeonservice

import (
	"errors"
	"os"
	"path/filepath"

	"github.com/katzenpost/hpqc/nike"
	"github.com/katzenpost/hpqc/nike/hybrid"
	"github.com/katzenpost/hpqc/nike/pem"
)

// DefaultNIKE is the scheme services, routers and directories use for their
// keys: the X25519 and CTIDH1024 hybrid.
var DefaultNIKE nike.Scheme = hybrid.X25519CTIDH1024

// LoadOrGenerateKeypair loads the keypair stored as name.private.pem and
// name.public.pem in dir, or generates and stores one if neither exists.
func LoadOrGenerateKeypair(dir, name string, scheme nike.Scheme) (nike.PublicKey, nike.PrivateKey, error) {
	privFile := filepath.Join(dir, name+".private.pem")
	pubFile := filepath.Join(dir, name+".public.pem")
	_, privErr := os.Stat(privFile)
	_, pubErr := os.Stat(pubFile)
	switch {
	case privErr == nil && pubErr == nil:
		priv, err := pem.FromPrivatePEMFile(privFile, scheme)
		if err != nil {
			return nil, nil, err
		}
		pub, err := pem.FromPublicPEMFile(pubFile, scheme)
		if err != nil {
			return nil, nil, err
		}
		if string(scheme.DerivePublicKey(priv).Bytes()) != string(pub.Bytes()) {
			return nil, nil, errors.New("pigeonservice: stored public key does not match the private key")
		}
		return pub, priv, nil
	case os.IsNotExist(privErr) && os.IsNotExist(pubErr):
		pub, priv, err := scheme.GenerateKeyPair()
		if err != nil {
			return nil, nil, err
		}
		if err := pem.PrivateKeyToFile(privFile, priv, scheme); err != nil {
			return nil, nil, err
		}
		if err := pem.PublicKeyToFile(pubFile, pub, scheme); err != nil {
			return nil, nil, err
		}
		return pub, priv, nil
	default:
		return nil, nil, errors.New("pigeonservice: " + name + " key files must both exist or both be absent")
	}
}

// PluginParams is what a router or a directory publishes in the PKI.
func PluginParams(key *PluginKey) map[string]any {
	return map[string]any{
		ParamNIKEScheme: key.Scheme.Name(),
		ParamPublicKey:  key.Public.Bytes(),
	}
}

// PluginPublicKey reads a router's or a directory's public key from what it
// published in the PKI.
func PluginPublicKey(node *ServiceNode, scheme nike.Scheme) (nike.PublicKey, error) {
	name, _ := node.Params[ParamNIKEScheme].(string)
	if name != scheme.Name() {
		return nil, errors.New("pigeonservice: service node publishes no key for " + scheme.Name())
	}
	raw, ok := node.Params[ParamPublicKey].([]byte)
	if !ok {
		return nil, errors.New("pigeonservice: service node publishes no public key")
	}
	return scheme.UnmarshalBinaryPublicKey(raw)
}

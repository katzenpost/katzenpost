// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package client

import (
	"errors"

	"github.com/katzenpost/hpqc/nike"
	"github.com/katzenpost/hpqc/nike/schemes"
	"github.com/katzenpost/hpqc/protocols/sealedbox"
	"github.com/katzenpost/hpqc/util"

	"github.com/katzenpost/katzenpost/client/thin"
)

// The NIKE and sealed box handlers are pure cryptography served by hpqc,
// with no mixnet IO; they reply synchronously like the voucher handlers, so
// a thin client needs no cryptography of its own. Keys travel as opaque
// bytes; the daemon keeps none of them.

func errorCode(err error) uint8 {
	if err != nil {
		return thin.ThinClientErrorInvalidRequest
	}
	return thin.ThinClientSuccess
}

func (d *Daemon) nikeGenerateKeyPair(request *Request) {
	req := request.NIKEGenerateKeyPair
	pub, priv, err := generateKeyPair(req)
	if err != nil {
		d.log.Debugf("nikeGenerateKeyPair: %v", err)
	}
	d.sendError(request.AppID, &Response{
		AppID: request.AppID,
		NIKEGenerateKeyPairReply: &thin.NIKEGenerateKeyPairReply{
			QueryID:    req.QueryID,
			PublicKey:  pub,
			PrivateKey: priv,
			ErrorCode:  errorCode(err),
		},
	})
}

func (d *Daemon) nikeDeriveSecret(request *Request) {
	req := request.NIKEDeriveSecret
	ss, err := deriveSecret(req)
	if err != nil {
		d.log.Debugf("nikeDeriveSecret: %v", err)
	}
	d.sendError(request.AppID, &Response{
		AppID: request.AppID,
		NIKEDeriveSecretReply: &thin.NIKEDeriveSecretReply{
			QueryID:      req.QueryID,
			SharedSecret: ss,
			ErrorCode:    errorCode(err),
		},
	})
}

func (d *Daemon) boxSeal(request *Request) {
	req := request.BoxSeal
	ciphertext, err := sealBox(req)
	if err != nil {
		d.log.Debugf("boxSeal: %v", err)
	}
	d.sendError(request.AppID, &Response{
		AppID: request.AppID,
		BoxSealReply: &thin.BoxSealReply{
			QueryID:    req.QueryID,
			Ciphertext: ciphertext,
			ErrorCode:  errorCode(err),
		},
	})
}

func (d *Daemon) boxOpen(request *Request) {
	req := request.BoxOpen
	plaintext, err := openBox(req)
	if err != nil {
		d.log.Debugf("boxOpen: %v", err)
	}
	d.sendError(request.AppID, &Response{
		AppID: request.AppID,
		BoxOpenReply: &thin.BoxOpenReply{
			QueryID:   req.QueryID,
			Plaintext: plaintext,
			ErrorCode: errorCode(err),
		},
	})
}

func nikeScheme(name string) (nike.Scheme, error) {
	scheme := schemes.ByName(name)
	if scheme == nil {
		return nil, errors.New("unknown NIKE scheme")
	}
	return scheme, nil
}

func generateKeyPair(req *thin.NIKEGenerateKeyPair) ([]byte, []byte, error) {
	scheme, err := nikeScheme(req.NIKEScheme)
	if err != nil {
		return nil, nil, err
	}
	pub, priv, err := scheme.GenerateKeyPair()
	if err != nil {
		return nil, nil, err
	}
	return pub.Bytes(), priv.Bytes(), nil
}

func deriveSecret(req *thin.NIKEDeriveSecret) ([]byte, error) {
	scheme, err := nikeScheme(req.NIKEScheme)
	if err != nil {
		return nil, err
	}
	priv, err := scheme.UnmarshalBinaryPrivateKey(req.PrivateKey)
	if err != nil {
		return nil, err
	}
	pub, err := scheme.UnmarshalBinaryPublicKey(req.PublicKey)
	if err != nil {
		return nil, err
	}
	ss := scheme.DeriveSecret(priv, pub)
	if len(ss) == 0 || util.CtIsZero(ss) {
		return nil, errors.New("degenerate shared secret")
	}
	return ss, nil
}

func sealBox(req *thin.BoxSeal) ([]byte, error) {
	scheme, err := nikeScheme(req.NIKEScheme)
	if err != nil {
		return nil, err
	}
	pub, err := scheme.UnmarshalBinaryPublicKey(req.PublicKey)
	if err != nil {
		return nil, err
	}
	return sealedbox.NewScheme(scheme).Seal(pub, req.Plaintext)
}

func openBox(req *thin.BoxOpen) ([]byte, error) {
	scheme, err := nikeScheme(req.NIKEScheme)
	if err != nil {
		return nil, err
	}
	priv, err := scheme.UnmarshalBinaryPrivateKey(req.PrivateKey)
	if err != nil {
		return nil, err
	}
	return sealedbox.NewScheme(scheme).Open(priv, scheme.DerivePublicKey(priv), req.Ciphertext)
}

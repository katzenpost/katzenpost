// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package client

import (
	"errors"

	"github.com/katzenpost/hpqc/nike/schemes"
	"github.com/katzenpost/hpqc/protocols/sealedbox"

	"github.com/katzenpost/katzenpost/client/thin"
)

// boxSeal is pure cryptography served by hpqc/protocols/sealedbox, with no
// mixnet IO; it replies synchronously like the voucher handlers.
func (d *Daemon) boxSeal(request *Request) {
	conn := d.listener.getConnection(request.AppID)
	if conn == nil {
		d.log.Errorf(errNoConnectionForAppID, request.AppID[:])
		return
	}
	ciphertext, err := sealBox(request.BoxSeal)
	if err != nil {
		d.log.Debugf("boxSeal: %v", err)
		d.sendError(request.AppID, &Response{
			AppID: request.AppID,
			BoxSealReply: &thin.BoxSealReply{
				QueryID:   request.BoxSeal.QueryID,
				ErrorCode: thin.ThinClientErrorInvalidRequest,
			},
		})
		return
	}
	conn.sendResponse(&Response{
		AppID: request.AppID,
		BoxSealReply: &thin.BoxSealReply{
			QueryID:    request.BoxSeal.QueryID,
			Ciphertext: ciphertext,
			ErrorCode:  thin.ThinClientSuccess,
		},
	})
}

func sealBox(req *thin.BoxSeal) ([]byte, error) {
	scheme := schemes.ByName(req.NIKEScheme)
	if scheme == nil {
		return nil, errors.New("unknown NIKE scheme")
	}
	pub, err := scheme.UnmarshalBinaryPublicKey(req.PublicKey)
	if err != nil {
		return nil, err
	}
	return sealedbox.NewScheme(scheme).Seal(pub, req.Plaintext)
}

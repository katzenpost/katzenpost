// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package client

import (
	"errors"

	"github.com/katzenpost/hpqc/voucher"

	"github.com/katzenpost/katzenpost/client/thin"
)

// The four voucher handlers are pure cryptography served by hpqc/voucher,
// with no mixnet IO; they reply synchronously like newKeypair. The thin
// client holds all key material as opaque bytes. Seeds are not exposed over
// the wire, so the daemon passes nil to hpqc and gets fresh randomness (a
// random reply keypair, a random salt, a random seal).

// voucherErrorCode maps an hpqc/voucher error to a thin client error code.
func voucherErrorCode(err error) uint8 {
	switch {
	case errors.Is(err, voucher.ErrVoucherHashMismatch):
		return thin.ThinClientErrorVoucherHashMismatch
	case errors.Is(err, voucher.ErrSignatureVerificationFailed):
		return thin.ThinClientErrorVoucherSignatureInvalid
	case errors.Is(err, voucher.ErrSealOpenFailed):
		return thin.ThinClientErrorVoucherSealOpenFailed
	default:
		return thin.ThinClientErrorInvalidRequest
	}
}

func (d *Daemon) voucherMint(request *Request) {
	conn := d.listener.getConnection(request.AppID)
	if conn == nil {
		d.log.Errorf(errNoConnectionForAppID, request.AppID[:])
		return
	}
	result, err := voucher.VoucherMint(
		request.VoucherMint.MessageWriteCap,
		request.VoucherMint.DisplayName,
		nil,
	)
	if err != nil {
		d.sendError(request.AppID, &Response{
			AppID: request.AppID,
			VoucherMintReply: &thin.VoucherMintReply{
				QueryID:   request.VoucherMint.QueryID,
				ErrorCode: voucherErrorCode(err),
			},
		})
		return
	}
	conn.sendResponse(&Response{
		AppID: request.AppID,
		VoucherMintReply: &thin.VoucherMintReply{
			QueryID:          request.VoucherMint.QueryID,
			Voucher:          result.Voucher,
			VoucherPayload:   result.VoucherPayload,
			VoucherWriteCap:  result.VoucherWriteCap,
			VoucherReadCap:   result.VoucherReadCap,
			VoucherSecretKey: result.VoucherSecretKey,
			VoucherPublicKey: result.VoucherPublicKey,
			ErrorCode:        thin.ThinClientSuccess,
		},
	})
}

func (d *Daemon) voucherInduct(request *Request) {
	conn := d.listener.getConnection(request.AppID)
	if conn == nil {
		d.log.Errorf(errNoConnectionForAppID, request.AppID[:])
		return
	}
	result, err := voucher.VoucherInduct(
		request.VoucherInduct.Voucher,
		request.VoucherInduct.VoucherPayload,
		request.VoucherInduct.WhoReply,
		nil,
		nil,
	)
	if err != nil {
		d.sendError(request.AppID, &Response{
			AppID: request.AppID,
			VoucherInductReply: &thin.VoucherInductReply{
				QueryID:   request.VoucherInduct.QueryID,
				ErrorCode: voucherErrorCode(err),
			},
		})
		return
	}
	conn.sendResponse(&Response{
		AppID: request.AppID,
		VoucherInductReply: &thin.VoucherInductReply{
			QueryID:               request.VoucherInduct.QueryID,
			DisplayName:           result.DisplayName,
			MutatedMessageReadCap: result.MutatedMessageReadCap,
			SealedReply:           result.SealedReply,
			VoucherWriteCap:       result.VoucherWriteCap,
			VoucherReadCap:        result.VoucherReadCap,
			Salt:                  result.Salt,
			ErrorCode:             thin.ThinClientSuccess,
		},
	})
}

func (d *Daemon) voucherOpen(request *Request) {
	conn := d.listener.getConnection(request.AppID)
	if conn == nil {
		d.log.Errorf(errNoConnectionForAppID, request.AppID[:])
		return
	}
	result, err := voucher.VoucherOpenReply(
		request.VoucherOpen.VoucherSecretKey,
		request.VoucherOpen.SealedReply,
		request.VoucherOpen.MessageWriteCap,
	)
	if err != nil {
		d.sendError(request.AppID, &Response{
			AppID: request.AppID,
			VoucherOpenReply: &thin.VoucherOpenReply{
				QueryID:   request.VoucherOpen.QueryID,
				ErrorCode: voucherErrorCode(err),
			},
		})
		return
	}
	conn.sendResponse(&Response{
		AppID: request.AppID,
		VoucherOpenReply: &thin.VoucherOpenReply{
			QueryID:                request.VoucherOpen.QueryID,
			WhoReply:               result.WhoReply,
			Salt:                   result.Salt,
			MutatedMessageWriteCap: result.MutatedMessageWriteCap,
			ErrorCode:              thin.ThinClientSuccess,
		},
	})
}

func (d *Daemon) voucherDeriveStream(request *Request) {
	conn := d.listener.getConnection(request.AppID)
	if conn == nil {
		d.log.Errorf(errNoConnectionForAppID, request.AppID[:])
		return
	}
	result, err := voucher.DeriveVoucherStream(request.VoucherDeriveStream.Voucher)
	if err != nil {
		d.sendError(request.AppID, &Response{
			AppID: request.AppID,
			VoucherDeriveStreamReply: &thin.VoucherDeriveStreamReply{
				QueryID:   request.VoucherDeriveStream.QueryID,
				ErrorCode: voucherErrorCode(err),
			},
		})
		return
	}
	conn.sendResponse(&Response{
		AppID: request.AppID,
		VoucherDeriveStreamReply: &thin.VoucherDeriveStreamReply{
			QueryID:         request.VoucherDeriveStream.QueryID,
			VoucherWriteCap: result.VoucherWriteCap,
			VoucherReadCap:  result.VoucherReadCap,
			ErrorCode:       thin.ThinClientSuccess,
		},
	})
}

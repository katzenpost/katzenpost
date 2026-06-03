// SPDX-FileCopyrightText: (c) 2024, 2025  David Stainton.
// SPDX-License-Identifier: AGPL-3.0-only
package client

import (
	"github.com/katzenpost/katzenpost/client/thin"
	sphinxConstants "github.com/katzenpost/katzenpost/core/sphinx/constants"
)

func IntoThinResponse(r *Response) *thin.Response {
	return &thin.Response{
		SessionTokenReply:         r.SessionTokenReply,
		ShutdownEvent:             r.ShutdownEvent,
		ConnectionStatusEvent:     r.ConnectionStatusEvent,
		NewPKIDocumentEvent:       r.NewPKIDocumentEvent,
		MessageSentEvent:          r.MessageSentEvent,
		MessageReplyEvent:         r.MessageReplyEvent,
		MessageIDGarbageCollected: r.MessageIDGarbageCollected,

		// New Pigeonhole API:
		NewKeypairReply:                      r.NewKeypairReply,
		EncryptReadReply:                     r.EncryptReadReply,
		EncryptWriteReply:                    r.EncryptWriteReply,
		StartResendingEncryptedMessageReply:  r.StartResendingEncryptedMessageReply,
		WriteStreamReply:                    r.WriteStreamReply,
		ReadStreamReply:                     r.ReadStreamReply,
		CancelResendingEncryptedMessageReply: r.CancelResendingEncryptedMessageReply,
		StartResendingCopyCommandReply:       r.StartResendingCopyCommandReply,
		CancelResendingCopyCommandReply:      r.CancelResendingCopyCommandReply,
		NextMessageBoxIndexReply:             r.NextMessageBoxIndexReply,
		GetMessageBoxIndexCounterReply:       r.GetMessageBoxIndexCounterReply,
		GetPKIDocumentReply:                  r.GetPKIDocumentReply,

		// Copy Channel API:
		CreateCourierEnvelopesFromPayloadReply:          r.CreateCourierEnvelopesFromPayloadReply,
		CreateCourierEnvelopesFromPayloadsReply:         r.CreateCourierEnvelopesFromPayloadsReply,
		CreateCourierEnvelopesFromTombstoneRangeReply:   r.CreateCourierEnvelopesFromTombstoneRangeReply,

		// Contact Voucher API:
		VoucherMintReply:         r.VoucherMintReply,
		VoucherInductReply:       r.VoucherInductReply,
		VoucherOpenReply:         r.VoucherOpenReply,
		VoucherDeriveStreamReply: r.VoucherDeriveStreamReply,
	}
}

type Response struct {
	// AppID must be a unique identity for the client application
	// that is receiving this Response.
	AppID *[AppIDLength]byte

	SessionTokenReply *thin.SessionTokenReply

	ShutdownEvent *thin.ShutdownEvent

	ConnectionStatusEvent *thin.ConnectionStatusEvent

	NewPKIDocumentEvent *thin.NewPKIDocumentEvent

	MessageSentEvent *thin.MessageSentEvent

	MessageReplyEvent *thin.MessageReplyEvent

	MessageIDGarbageCollected *thin.MessageIDGarbageCollected

	// New Pigeonhole API:

	NewKeypairReply *thin.NewKeypairReply

	EncryptReadReply *thin.EncryptReadReply

	EncryptWriteReply *thin.EncryptWriteReply

	StartResendingEncryptedMessageReply *thin.StartResendingEncryptedMessageReply

	WriteStreamReply *thin.WriteStreamReply

	ReadStreamReply *thin.ReadStreamReply

	CancelResendingEncryptedMessageReply *thin.CancelResendingEncryptedMessageReply

	StartResendingCopyCommandReply *thin.StartResendingCopyCommandReply

	CancelResendingCopyCommandReply *thin.CancelResendingCopyCommandReply

	NextMessageBoxIndexReply *thin.NextMessageBoxIndexReply

	GetMessageBoxIndexCounterReply *thin.GetMessageBoxIndexCounterReply

	GetPKIDocumentReply *thin.GetPKIDocumentReply

	// Copy Channel API:

	CreateCourierEnvelopesFromPayloadReply *thin.CreateCourierEnvelopesFromPayloadReply

	CreateCourierEnvelopesFromPayloadsReply *thin.CreateCourierEnvelopesFromPayloadsReply

	CreateCourierEnvelopesFromTombstoneRangeReply *thin.CreateCourierEnvelopesFromTombstoneRangeReply

	// Contact Voucher API:

	VoucherMintReply *thin.VoucherMintReply

	VoucherInductReply *thin.VoucherInductReply

	VoucherOpenReply *thin.VoucherOpenReply

	VoucherDeriveStreamReply *thin.VoucherDeriveStreamReply
}

func FromThinRequest(r *thin.Request, appid *[AppIDLength]byte) *Request {
	return &Request{
		AppID: appid,

		// New Pigeonhole API:
		NewKeypair:                      r.NewKeypair,
		EncryptRead:                     r.EncryptRead,
		EncryptWrite:                    r.EncryptWrite,
		StartResendingEncryptedMessage:  r.StartResendingEncryptedMessage,
		CancelResendingEncryptedMessage: r.CancelResendingEncryptedMessage,
		StartResendingCopyCommand:       r.StartResendingCopyCommand,
		CancelResendingCopyCommand:      r.CancelResendingCopyCommand,
		NextMessageBoxIndex:             r.NextMessageBoxIndex,
		GetMessageBoxIndexCounter:       r.GetMessageBoxIndexCounter,
		GetPKIDocument:                  r.GetPKIDocument,

		// Copy Channel API:
		CreateCourierEnvelopesFromPayload:          r.CreateCourierEnvelopesFromPayload,
		CreateCourierEnvelopesFromPayloads:         r.CreateCourierEnvelopesFromPayloads,
		CreateCourierEnvelopesFromTombstoneRange:   r.CreateCourierEnvelopesFromTombstoneRange,

		// Contact Voucher API:
		VoucherMint:         r.VoucherMint,
		VoucherInduct:       r.VoucherInduct,
		VoucherOpen:         r.VoucherOpen,
		VoucherDeriveStream: r.VoucherDeriveStream,

		SessionToken: r.SessionToken,
		SendMessage:  r.SendMessage,
		ThinClose:    r.ThinClose,

		WriteStream: r.WriteStream,
		ReadStream:  r.ReadStream,
	}
}

type SendLoopDecoy struct {
}

type Request struct {
	// AppID must be a unique identity for the client application
	// that is sending this Request.
	AppID *[AppIDLength]byte

	// New Pigeonhole API:

	NewKeypair *thin.NewKeypair

	EncryptRead *thin.EncryptRead

	EncryptWrite *thin.EncryptWrite

	StartResendingEncryptedMessage *thin.StartResendingEncryptedMessage

	CancelResendingEncryptedMessage *thin.CancelResendingEncryptedMessage

	StartResendingCopyCommand *thin.StartResendingCopyCommand

	CancelResendingCopyCommand *thin.CancelResendingCopyCommand

	NextMessageBoxIndex *thin.NextMessageBoxIndex

	GetMessageBoxIndexCounter *thin.GetMessageBoxIndexCounter

	GetPKIDocument *thin.GetPKIDocument

	// Copy Channel API:

	CreateCourierEnvelopesFromPayload *thin.CreateCourierEnvelopesFromPayload

	CreateCourierEnvelopesFromPayloads *thin.CreateCourierEnvelopesFromPayloads

	CreateCourierEnvelopesFromTombstoneRange *thin.CreateCourierEnvelopesFromTombstoneRange

	// Contact Voucher API:

	VoucherMint *thin.VoucherMint

	VoucherInduct *thin.VoucherInduct

	VoucherOpen *thin.VoucherOpen

	VoucherDeriveStream *thin.VoucherDeriveStream

	SessionToken *thin.SessionToken

	// Core functionality

	ThinClose *thin.ThinClose

	// Decoys

	SendLoopDecoy *SendLoopDecoy

	// Legacy API

	SendMessage *thin.SendMessage

	// ResendARQ carries a SURB ID that the ARQ timer wants to retransmit.
	// Emitted by the listener's scheduler (never from a thin client), so
	// resends travel through the same fair, Poisson-gated path as fresh
	// sends. egressWorker routes it to arqDoResend.
	ResendARQ *[sphinxConstants.SURBIDLength]byte

	// WriteStream requests a windowed SACK write of a whole multi-box payload.
	WriteStream *thin.WriteStream

	// ReadStream requests a windowed SACK read of many sequential boxes.
	ReadStream *thin.ReadStream

	// SACKBoxSend carries one box of a SACK write through the Poisson-gated
	// egress path. Emitted by the SACK controller (never from a thin client),
	// so each box send is rate-limited like any other send. egressWorker
	// routes it to sackDoBoxSend.
	SACKBoxSend *sackBoxSend
}

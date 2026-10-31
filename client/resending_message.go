// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package client

import (
	"fmt"

	"github.com/katzenpost/katzenpost/client/thin"
	"github.com/katzenpost/katzenpost/core/utils"
)

// StartResendingMessage is the plain ARQ: it carries an opaque payload to any
// mixnet service and retransmits it until the service replies. It shares the
// pigeonhole ARQ's machinery: the request itself is dispatched on a Poisson
// tick, and every retransmission goes through enqueueResend and arqDoResend
// with a fresh SURB. Only the reply handling differs: the first reply ends the
// exchange and is passed to the thin client unchanged.

func validateStartResendingMessage(req *thin.StartResendingMessage, maxPayloadLen int) error {
	if req.QueryID == nil {
		return fmt.Errorf("QueryID is nil")
	}
	if req.MessageID == nil {
		return fmt.Errorf("MessageID is nil")
	}
	return validateSendMessageRequest(req.DestinationIdHash, req.RecipientQueueID, req.Payload, maxPayloadLen)
}

func (d *Daemon) startResendingMessage(request *Request) {
	req := request.StartResendingMessage
	if err := validateStartResendingMessage(req, d.client.geo.UserForwardPayloadLength); err != nil {
		d.log.Errorf("startResendingMessage: %v", err)
		d.sendStartResendingMessageError(request, thin.ThinClientErrorInvalidRequest)
		return
	}

	d.lockReply()
	_, duplicate := d.arqEnvelopeHashMap[*req.MessageID]
	d.replyLock.Unlock()
	if duplicate {
		d.log.Errorf("startResendingMessage: MessageID already in flight")
		d.sendStartResendingMessageError(request, thin.ThinClientErrorInvalidRequest)
		return
	}

	message := &ARQMessage{
		MessageType:       ARQMessageTypePlain,
		AppID:             request.AppID,
		QueryID:           req.QueryID,
		EnvelopeHash:      req.MessageID,
		DestinationIdHash: req.DestinationIdHash,
		RecipientQueueID:  req.RecipientQueueID,
		Payload:           req.Payload,
	}
	if err := d.arqSend(message, *req.MessageID); err != nil {
		d.log.Errorf("startResendingMessage: %s", err)
		d.sendStartResendingMessageError(request, thin.ThinClientErrorInternalError)
	}
}

func (d *Daemon) sendStartResendingMessageError(request *Request, errorCode uint8) {
	d.sendError(request.AppID, &Response{
		AppID: request.AppID,
		StartResendingMessageReply: &thin.StartResendingMessageReply{
			QueryID:   request.StartResendingMessage.QueryID,
			MessageID: request.StartResendingMessage.MessageID,
			ErrorCode: errorCode,
		},
	})
}

// handlePlainARQReply ends a plain ARQ exchange with the service's reply.
func (d *Daemon) handlePlainARQReply(arqMessage *ARQMessage, payload []byte, conn *incomingConn) {
	if !d.claimARQTerminal(arqMessage) {
		return
	}
	d.deliverARQResponse(arqMessage.AppID, conn, &Response{
		AppID: arqMessage.AppID,
		StartResendingMessageReply: &thin.StartResendingMessageReply{
			QueryID:   arqMessage.QueryID,
			MessageID: arqMessage.EnvelopeHash,
			Payload:   payload,
			ErrorCode: thin.ThinClientSuccess,
		},
	})
}

func (d *Daemon) cancelResendingMessage(request *Request) {
	conn := d.listener.getConnection(request.AppID)
	if conn == nil {
		d.log.Errorf(errNoConnectionForAppID, request.AppID[:])
		return
	}
	req := request.CancelResendingMessage
	if req.QueryID == nil || req.MessageID == nil {
		d.sendError(request.AppID, &Response{
			AppID: request.AppID,
			CancelResendingMessageReply: &thin.CancelResendingMessageReply{
				QueryID:   req.QueryID,
				ErrorCode: thin.ThinClientErrorInvalidRequest,
			},
		})
		return
	}

	d.lockReply()
	var arqMessage *ARQMessage
	if surbID, ok := d.arqEnvelopeHashMap[*req.MessageID]; ok && surbID != nil {
		arqMessage = d.arqSurbIDMap[*surbID]
		if arqMessage != nil && arqMessage.MessageType == ARQMessageTypePlain && *arqMessage.AppID == *request.AppID {
			delete(d.arqSurbIDMap, *surbID)
			delete(d.arqEnvelopeHashMap, *req.MessageID)
			utils.ExplicitBzero(arqMessage.SURBDecryptionKeys)
		} else {
			arqMessage = nil
		}
	}
	d.replyLock.Unlock()

	if arqMessage != nil {
		if arqMessage.SURBID != nil && d.arqTimerQueue != nil {
			d.arqTimerQueue.Cancel(arqMessage.SURBID)
		}
		conn.sendResponse(&Response{
			AppID: request.AppID,
			StartResendingMessageReply: &thin.StartResendingMessageReply{
				QueryID:   arqMessage.QueryID,
				MessageID: req.MessageID,
				ErrorCode: thin.ThinClientErrorStartResendingCancelled,
			},
		})
	}
	conn.sendResponse(&Response{
		AppID: request.AppID,
		CancelResendingMessageReply: &thin.CancelResendingMessageReply{
			QueryID:   req.QueryID,
			ErrorCode: thin.ThinClientSuccess,
		},
	})
}

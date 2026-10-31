// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package thin

import (
	"bytes"
	"context"
	"crypto/rand"
	"errors"
)

// StartResendingMessage sends payload to the mixnet service at destNode and
// destQueue and blocks until the service replies, returning the reply.
//
// The daemon retransmits the identical payload with a fresh SURB until a
// reply arrives. Every transmission leaves on the client's Poisson schedule,
// so retries look like any other traffic. The service must therefore treat a
// repeated payload as idempotent. If ctx ends first, the daemon is told to
// stop and ctx.Err() is returned.
func (t *ThinClient) StartResendingMessage(ctx context.Context, destNode *[32]byte, destQueue []byte, payload []byte) ([]byte, error) {
	if destNode == nil {
		return nil, errors.New("destNode cannot be nil")
	}
	messageID := new([32]byte)
	if _, err := rand.Read(messageID[:]); err != nil {
		return nil, err
	}
	queryID := t.NewQueryID()
	req := &Request{
		StartResendingMessage: &StartResendingMessage{
			QueryID:           queryID,
			MessageID:         messageID,
			DestinationIdHash: destNode,
			RecipientQueueID:  destQueue,
			Payload:           payload,
		},
	}

	t.inFlightResends.Store(*messageID, req)
	defer t.inFlightResends.Delete(*messageID)

	done := false
	defer func() {
		if !done {
			_ = t.CancelResendingMessage(messageID)
		}
	}()

	eventSink := t.EventSink()
	defer t.StopEventSink(eventSink)

	if err := t.writeMessage(req); err != nil {
		return nil, err
	}

	for {
		var event Event
		select {
		case event = <-eventSink:
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-t.HaltCh():
			done = true
			return nil, errHalting
		}

		switch v := event.(type) {
		case *StartResendingMessageReply:
			if v.QueryID == nil || !bytes.Equal(v.QueryID[:], queryID[:]) {
				continue
			}
			done = true
			if v.ErrorCode != ThinClientSuccess {
				return nil, errorCodeToSentinel(v.ErrorCode)
			}
			return v.Payload, nil
		case *ConnectionStatusEvent:
			t.setConnected(v.IsConnected)
		case *NewDocumentEvent:
		default:
		}
	}
}

// CancelResendingMessage stops the StartResendingMessage named by messageID.
// The blocked caller, if any, returns ErrStartResendingCancelled.
func (t *ThinClient) CancelResendingMessage(messageID *[32]byte) error {
	if messageID == nil {
		return errors.New("messageID cannot be nil")
	}
	t.inFlightResends.Delete(*messageID)
	if !t.IsConnected() {
		return nil
	}

	queryID := t.NewQueryID()
	req := &Request{
		CancelResendingMessage: &CancelResendingMessage{
			QueryID:   queryID,
			MessageID: messageID,
		},
	}
	eventSink := t.EventSink()
	defer t.StopEventSink(eventSink)
	if err := t.writeMessage(req); err != nil {
		return err
	}
	for {
		var event Event
		select {
		case event = <-eventSink:
		case <-t.HaltCh():
			return errHalting
		}
		switch v := event.(type) {
		case *CancelResendingMessageReply:
			if v.QueryID == nil || !bytes.Equal(v.QueryID[:], queryID[:]) {
				continue
			}
			if v.ErrorCode != ThinClientSuccess {
				return errors.New(ThinClientErrorToString(v.ErrorCode))
			}
			return nil
		case *ConnectionStatusEvent:
			t.setConnected(v.IsConnected)
		case *NewDocumentEvent:
		default:
		}
	}
}

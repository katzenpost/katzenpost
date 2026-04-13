// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package thin

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	cpki "github.com/katzenpost/katzenpost/core/pki"
)

func TestShutdownEventString(t *testing.T) {
	e := &ShutdownEvent{}
	require.Equal(t, "ShutdownEvent", e.String())
}

func TestDaemonDisconnectedEventString(t *testing.T) {
	t.Run("graceful", func(t *testing.T) {
		e := &DaemonDisconnectedEvent{IsGraceful: true}
		require.Contains(t, e.String(), "graceful")
	})

	t.Run("unexpected", func(t *testing.T) {
		e := &DaemonDisconnectedEvent{IsGraceful: false, Err: errors.New("connection reset")}
		s := e.String()
		require.Contains(t, s, "unexpected")
		require.Contains(t, s, "connection reset")
	})

	t.Run("unexpected nil error", func(t *testing.T) {
		e := &DaemonDisconnectedEvent{IsGraceful: false}
		require.Contains(t, e.String(), "unexpected")
	})
}

func TestConnectionStatusEventString(t *testing.T) {
	t.Run("connected", func(t *testing.T) {
		e := &ConnectionStatusEvent{IsConnected: true}
		s := e.String()
		require.Contains(t, s, "true")
		require.NotContains(t, s, "nil")
	})

	t.Run("disconnected with error", func(t *testing.T) {
		e := &ConnectionStatusEvent{IsConnected: false, Err: errors.New("timeout")}
		s := e.String()
		require.Contains(t, s, "false")
		require.Contains(t, s, "timeout")
	})
}

func TestMessageReplyEventString(t *testing.T) {
	msgID := &[MessageIDLength]byte{}
	copy(msgID[:], []byte("test-message-id!"))

	t.Run("success", func(t *testing.T) {
		e := &MessageReplyEvent{
			MessageID: msgID,
			Payload:   []byte("hello"),
			ErrorCode: ThinClientSuccess,
		}
		s := e.String()
		require.Contains(t, s, "5 bytes")
	})

	t.Run("with reply index", func(t *testing.T) {
		idx := uint8(3)
		e := &MessageReplyEvent{
			MessageID:  msgID,
			Payload:    []byte("data"),
			ReplyIndex: &idx,
			ErrorCode:  ThinClientSuccess,
		}
		require.Contains(t, e.String(), "replyIndex=3")
	})

	t.Run("error", func(t *testing.T) {
		e := &MessageReplyEvent{
			MessageID: msgID,
			ErrorCode: ThinClientErrorTimeout,
		}
		require.Contains(t, e.String(), "failed")
		require.Contains(t, e.String(), "Timeout")
	})
}

func TestMessageSentEventString(t *testing.T) {
	msgID := &[MessageIDLength]byte{}
	copy(msgID[:], []byte("sent-message-id!"))

	t.Run("success", func(t *testing.T) {
		e := &MessageSentEvent{
			MessageID: msgID,
			SentAt:    time.Now(),
		}
		s := e.String()
		require.Contains(t, s, "MessageSent")
		require.Contains(t, s, fmt.Sprintf("%x", msgID[:]))
	})

	t.Run("with error", func(t *testing.T) {
		e := &MessageSentEvent{
			MessageID: msgID,
			Err:       "send failed",
		}
		require.Contains(t, e.String(), "failed")
		require.Contains(t, e.String(), "send failed")
	})
}

func TestMessageIDGarbageCollectedString(t *testing.T) {
	msgID := &[MessageIDLength]byte{}
	copy(msgID[:], []byte("gc-message-id!!!"))
	e := &MessageIDGarbageCollected{MessageID: msgID}
	require.Contains(t, e.String(), "GarbageCollected")
}

func TestNewDocumentEventString(t *testing.T) {
	e := &NewDocumentEvent{
		Document: &cpki.Document{Epoch: 42},
	}
	require.Contains(t, e.String(), "42")
}

func TestNewKeypairReplyString(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		e := &NewKeypairReply{ErrorCode: ThinClientSuccess}
		require.Contains(t, e.String(), "success")
	})

	t.Run("error", func(t *testing.T) {
		e := &NewKeypairReply{ErrorCode: ThinClientErrorInvalidRequest}
		require.Contains(t, e.String(), "error")
	})
}

func TestEncryptReadReplyString(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		e := &EncryptReadReply{
			MessageCiphertext: make([]byte, 100),
			ErrorCode:         ThinClientSuccess,
		}
		require.Contains(t, e.String(), "100 bytes")
	})

	t.Run("error", func(t *testing.T) {
		e := &EncryptReadReply{ErrorCode: ThinClientErrorInternalError}
		require.Contains(t, e.String(), "error")
	})
}

func TestEncryptWriteReplyString(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		e := &EncryptWriteReply{
			MessageCiphertext: make([]byte, 200),
			ErrorCode:         ThinClientSuccess,
		}
		require.Contains(t, e.String(), "200 bytes")
	})

	t.Run("error", func(t *testing.T) {
		e := &EncryptWriteReply{ErrorCode: ThinClientErrorInternalError}
		require.Contains(t, e.String(), "error")
	})
}

func TestStartResendingEncryptedMessageReplyString(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		courierHash := &[32]byte{}
		e := &StartResendingEncryptedMessageReply{
			Plaintext:           []byte("hello"),
			CourierIdentityHash: courierHash,
			ErrorCode:           ThinClientSuccess,
		}
		require.Contains(t, e.String(), "5 bytes")
	})

	t.Run("error", func(t *testing.T) {
		e := &StartResendingEncryptedMessageReply{
			ErrorCode: ThinClientErrorTimeout,
		}
		require.Contains(t, e.String(), "error")
	})
}

func TestCancelResendingEncryptedMessageReplyString(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		e := &CancelResendingEncryptedMessageReply{ErrorCode: ThinClientSuccess}
		require.Contains(t, e.String(), "success")
	})

	t.Run("error", func(t *testing.T) {
		e := &CancelResendingEncryptedMessageReply{ErrorCode: ThinClientErrorInternalError}
		require.Contains(t, e.String(), "error")
	})
}

func TestStartResendingCopyCommandReplyString(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		e := &StartResendingCopyCommandReply{ErrorCode: ThinClientSuccess}
		require.Contains(t, e.String(), "success")
	})

	t.Run("error", func(t *testing.T) {
		e := &StartResendingCopyCommandReply{ErrorCode: ThinClientPropagationError}
		require.Contains(t, e.String(), "error")
	})
}

func TestCancelResendingCopyCommandReplyString(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		e := &CancelResendingCopyCommandReply{ErrorCode: ThinClientSuccess}
		require.Contains(t, e.String(), "success")
	})

	t.Run("error", func(t *testing.T) {
		e := &CancelResendingCopyCommandReply{ErrorCode: ThinClientErrorInternalError}
		require.Contains(t, e.String(), "error")
	})
}

func TestNextMessageBoxIndexReplyString(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		e := &NextMessageBoxIndexReply{ErrorCode: ThinClientSuccess}
		require.Contains(t, e.String(), "success")
	})

	t.Run("error", func(t *testing.T) {
		e := &NextMessageBoxIndexReply{ErrorCode: ThinClientErrorInvalidRequest}
		require.Contains(t, e.String(), "error")
	})
}

func TestCreateCourierEnvelopesFromPayloadReplyString(t *testing.T) {
	queryID := &[QueryIDLength]byte{}

	t.Run("success", func(t *testing.T) {
		e := &CreateCourierEnvelopesFromPayloadReply{
			QueryID:   queryID,
			Envelopes: [][]byte{[]byte("a"), []byte("b")},
			ErrorCode: ThinClientSuccess,
		}
		require.Contains(t, e.String(), "numEnvelopes=2")
	})

	t.Run("error", func(t *testing.T) {
		e := &CreateCourierEnvelopesFromPayloadReply{
			QueryID:   queryID,
			ErrorCode: ThinClientErrorInternalError,
		}
		require.Contains(t, e.String(), "error")
	})
}

func TestCreateCourierEnvelopesFromPayloadsReplyString(t *testing.T) {
	queryID := &[QueryIDLength]byte{}

	t.Run("success", func(t *testing.T) {
		e := &CreateCourierEnvelopesFromPayloadsReply{
			QueryID:   queryID,
			Envelopes: [][]byte{[]byte("a")},
			Buffer:    []byte("buffered"),
			ErrorCode: ThinClientSuccess,
		}
		s := e.String()
		require.Contains(t, s, "numEnvelopes=1")
		require.Contains(t, s, "bufferLen=8")
	})

	t.Run("error", func(t *testing.T) {
		e := &CreateCourierEnvelopesFromPayloadsReply{
			QueryID:   queryID,
			ErrorCode: ThinClientErrorInternalError,
		}
		require.Contains(t, e.String(), "error")
	})
}

// Verify all event types implement the Event interface
func TestEventInterface(t *testing.T) {
	var _ Event = &ShutdownEvent{}
	var _ Event = &DaemonDisconnectedEvent{}
	var _ Event = &ConnectionStatusEvent{}
	var _ Event = &MessageReplyEvent{}
	var _ Event = &MessageSentEvent{}
	var _ Event = &MessageIDGarbageCollected{}
	var _ Event = &NewDocumentEvent{}
	var _ Event = &NewKeypairReply{}
	var _ Event = &EncryptReadReply{}
	var _ Event = &EncryptWriteReply{}
	var _ Event = &StartResendingEncryptedMessageReply{}
	var _ Event = &CancelResendingEncryptedMessageReply{}
	var _ Event = &StartResendingCopyCommandReply{}
	var _ Event = &CancelResendingCopyCommandReply{}
	var _ Event = &NextMessageBoxIndexReply{}
	var _ Event = &CreateCourierEnvelopesFromPayloadReply{}
	var _ Event = &CreateCourierEnvelopesFromPayloadsReply{}
	var _ Event = &CreateCourierEnvelopesFromTombstoneRangeReply{}
}

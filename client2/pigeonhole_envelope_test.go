// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package client2

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/client2/thin"
)

func TestChunkPayload(t *testing.T) {
	t.Run("single chunk", func(t *testing.T) {
		payload := []byte("hello")
		chunks := chunkPayload(payload, 100)
		require.Len(t, chunks, 1)
		require.Equal(t, payload, chunks[0])
	})

	t.Run("exact fit", func(t *testing.T) {
		payload := make([]byte, 100)
		for i := range payload {
			payload[i] = byte(i)
		}
		chunks := chunkPayload(payload, 100)
		require.Len(t, chunks, 1)
		require.Equal(t, payload, chunks[0])
	})

	t.Run("two chunks", func(t *testing.T) {
		payload := make([]byte, 150)
		for i := range payload {
			payload[i] = byte(i)
		}
		chunks := chunkPayload(payload, 100)
		require.Len(t, chunks, 2)
		require.Len(t, chunks[0], 100)
		require.Len(t, chunks[1], 50)
		// Verify content
		require.Equal(t, payload[:100], chunks[0])
		require.Equal(t, payload[100:], chunks[1])
	})

	t.Run("many chunks", func(t *testing.T) {
		payload := make([]byte, 1000)
		chunks := chunkPayload(payload, 300)
		require.Len(t, chunks, 4) // 300 + 300 + 300 + 100
		require.Len(t, chunks[0], 300)
		require.Len(t, chunks[1], 300)
		require.Len(t, chunks[2], 300)
		require.Len(t, chunks[3], 100)
	})

	t.Run("empty payload", func(t *testing.T) {
		chunks := chunkPayload([]byte{}, 100)
		require.Len(t, chunks, 0)
	})

	t.Run("nil payload", func(t *testing.T) {
		chunks := chunkPayload(nil, 100)
		require.Len(t, chunks, 0)
	})
}

func TestValidateStartResendingRequest(t *testing.T) {
	queryID := new([thin.QueryIDLength]byte)
	envHash := new([32]byte)
	envDesc := []byte("descriptor")
	ciphertext := []byte("ciphertext")

	t.Run("valid read", func(t *testing.T) {
		req := &thin.StartResendingEncryptedMessage{
			QueryID:            queryID,
			EnvelopeHash:       envHash,
			MessageCiphertext:  ciphertext,
			EnvelopeDescriptor: envDesc,
			ReadCap:            &dummyReadCap,
		}
		require.NoError(t, validateStartResendingRequest(req))
	})

	t.Run("valid write", func(t *testing.T) {
		req := &thin.StartResendingEncryptedMessage{
			QueryID:            queryID,
			EnvelopeHash:       envHash,
			MessageCiphertext:  ciphertext,
			EnvelopeDescriptor: envDesc,
			WriteCap:           &dummyWriteCap,
		}
		require.NoError(t, validateStartResendingRequest(req))
	})

	t.Run("nil QueryID", func(t *testing.T) {
		req := &thin.StartResendingEncryptedMessage{
			EnvelopeHash:       envHash,
			MessageCiphertext:  ciphertext,
			EnvelopeDescriptor: envDesc,
			ReadCap:            &dummyReadCap,
		}
		require.Error(t, validateStartResendingRequest(req))
	})

	t.Run("nil EnvelopeHash", func(t *testing.T) {
		req := &thin.StartResendingEncryptedMessage{
			QueryID:            queryID,
			MessageCiphertext:  ciphertext,
			EnvelopeDescriptor: envDesc,
			ReadCap:            &dummyReadCap,
		}
		require.Error(t, validateStartResendingRequest(req))
	})

	t.Run("empty ciphertext", func(t *testing.T) {
		req := &thin.StartResendingEncryptedMessage{
			QueryID:            queryID,
			EnvelopeHash:       envHash,
			MessageCiphertext:  []byte{},
			EnvelopeDescriptor: envDesc,
			ReadCap:            &dummyReadCap,
		}
		require.Error(t, validateStartResendingRequest(req))
	})

	t.Run("empty envelope descriptor", func(t *testing.T) {
		req := &thin.StartResendingEncryptedMessage{
			QueryID:           queryID,
			EnvelopeHash:      envHash,
			MessageCiphertext: ciphertext,
			ReadCap:           &dummyReadCap,
		}
		require.Error(t, validateStartResendingRequest(req))
	})

	t.Run("both ReadCap and WriteCap set", func(t *testing.T) {
		req := &thin.StartResendingEncryptedMessage{
			QueryID:            queryID,
			EnvelopeHash:       envHash,
			MessageCiphertext:  ciphertext,
			EnvelopeDescriptor: envDesc,
			ReadCap:            &dummyReadCap,
			WriteCap:           &dummyWriteCap,
		}
		require.Error(t, validateStartResendingRequest(req))
	})

	t.Run("neither ReadCap nor WriteCap set", func(t *testing.T) {
		req := &thin.StartResendingEncryptedMessage{
			QueryID:            queryID,
			EnvelopeHash:       envHash,
			MessageCiphertext:  ciphertext,
			EnvelopeDescriptor: envDesc,
		}
		require.Error(t, validateStartResendingRequest(req))
	})
}

func TestValidateEnvelopePayloadRequest(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		err := validateEnvelopePayloadRequest([]byte("data"), &dummyWriteCap, &dummyMessageBoxIndex, 100)
		require.NoError(t, err)
	})

	t.Run("nil write cap", func(t *testing.T) {
		err := validateEnvelopePayloadRequest([]byte("data"), nil, &dummyMessageBoxIndex, 100)
		require.Error(t, err)
		require.Contains(t, err.Error(), "WriteCap")
	})

	t.Run("nil start index", func(t *testing.T) {
		err := validateEnvelopePayloadRequest([]byte("data"), &dummyWriteCap, nil, 100)
		require.Error(t, err)
		require.Contains(t, err.Error(), "StartIndex")
	})

	t.Run("payload too large", func(t *testing.T) {
		bigPayload := make([]byte, 11*1024*1024)
		err := validateEnvelopePayloadRequest(bigPayload, &dummyWriteCap, &dummyMessageBoxIndex, 100)
		require.Error(t, err)
		require.Contains(t, err.Error(), "exceeds maximum")
	})

	t.Run("invalid geometry", func(t *testing.T) {
		err := validateEnvelopePayloadRequest([]byte("data"), &dummyWriteCap, &dummyMessageBoxIndex, 0)
		require.Error(t, err)
		require.Contains(t, err.Error(), "maxPayload")
	})

	t.Run("geometry too small", func(t *testing.T) {
		err := validateEnvelopePayloadRequest([]byte("data"), &dummyWriteCap, &dummyMessageBoxIndex, 4)
		require.Error(t, err)
		require.Contains(t, err.Error(), "maxPayload")
	})
}

// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package client2

import (
	"sync"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/op/go-logging.v1"

	"github.com/katzenpost/hpqc/bacap"
	"github.com/katzenpost/hpqc/hash"

	"github.com/katzenpost/katzenpost/client2/thin"
	"github.com/katzenpost/katzenpost/pigeonhole"
)

var (
	dummyStatefulReader  bacap.StatefulReader
	dummyStatefulWriter  bacap.StatefulWriter
	dummyWriteCap        bacap.WriteCap
	dummyReadCap         bacap.ReadCap
	dummyMessageBoxIndex bacap.MessageBoxIndex
)

func newValidationTestDaemon() *Daemon {
	return &Daemon{
		log: logging.MustGetLogger("test"),
	}
}

func TestReplicaError(t *testing.T) {
	err := &replicaError{code: 42}
	require.Contains(t, err.Error(), "42")
	require.Contains(t, err.Error(), "replica error code")
}

func TestGenerateUniqueChannelID(t *testing.T) {
	d := &Daemon{
		log:               logging.MustGetLogger("test"),
		newChannelMapXXX:  make(map[uint16]bool),
		newChannelMapLock: new(sync.RWMutex),
	}

	ids := make(map[uint16]bool)
	for i := 0; i < 100; i++ {
		id := d.generateUniqueChannelID()
		require.False(t, ids[id], "generated duplicate channel ID %d", id)
		require.NotEqual(t, uint16(0), id, "channel ID should never be 0")
		ids[id] = true
	}
}

func TestMapCourierErrorToThinClientError(t *testing.T) {
	tests := []struct {
		name     string
		input    uint8
		expected uint8
	}{
		{"success", pigeonhole.EnvelopeErrorSuccess, thin.ThinClientSuccess},
		{"invalid envelope", pigeonhole.EnvelopeErrorInvalidEnvelope, thin.ThinClientErrorInvalidRequest},
		{"cache corruption", pigeonhole.EnvelopeErrorCacheCorruption, thin.ThinClientErrorCourierCacheCorruption},
		{"propagation error", pigeonhole.EnvelopeErrorPropagationError, thin.ThinClientPropagationError},
		{"unknown code maps to internal error", 99, thin.ThinClientErrorInternalError},
		{"unknown code 255", 255, thin.ThinClientErrorInternalError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := mapCourierErrorToThinClientError(tt.input)
			require.Equal(t, tt.expected, result)
		})
	}
}

func TestValidateNewChannel(t *testing.T) {
	d := newValidationTestDaemon()

	t.Run("reader only", func(t *testing.T) {
		desc := &ChannelDescriptor{
			StatefulReader:      &dummyStatefulReader,
			EnvelopeDescriptors: make(map[[hash.HashSize]byte]*EnvelopeDescriptor),
		}
		isReader, isWriter, err := d.validateNewChannel(1, desc)
		require.NoError(t, err)
		require.True(t, isReader)
		require.False(t, isWriter)
	})

	t.Run("writer only", func(t *testing.T) {
		desc := &ChannelDescriptor{
			StatefulWriter:      &dummyStatefulWriter,
			EnvelopeDescriptors: make(map[[hash.HashSize]byte]*EnvelopeDescriptor),
		}
		isReader, isWriter, err := d.validateNewChannel(2, desc)
		require.NoError(t, err)
		require.False(t, isReader)
		require.True(t, isWriter)
	})

	t.Run("both nil", func(t *testing.T) {
		desc := &ChannelDescriptor{
			EnvelopeDescriptors: make(map[[hash.HashSize]byte]*EnvelopeDescriptor),
		}
		_, _, err := d.validateNewChannel(3, desc)
		require.Error(t, err)
		require.Contains(t, err.Error(), "bug 1")
	})

	t.Run("both set", func(t *testing.T) {
		desc := &ChannelDescriptor{
			StatefulReader:      &dummyStatefulReader,
			StatefulWriter:      &dummyStatefulWriter,
			EnvelopeDescriptors: make(map[[hash.HashSize]byte]*EnvelopeDescriptor),
		}
		_, _, err := d.validateNewChannel(4, desc)
		require.Error(t, err)
		require.Contains(t, err.Error(), "bug 2")
	})

	t.Run("nil envelope descriptors", func(t *testing.T) {
		desc := &ChannelDescriptor{
			StatefulReader: &dummyStatefulReader,
		}
		_, _, err := d.validateNewChannel(5, desc)
		require.Error(t, err)
		require.Contains(t, err.Error(), "bug 3")
	})
}

func TestValidateReadReplySignature(t *testing.T) {
	d := newValidationTestDaemon()

	t.Run("zero signature", func(t *testing.T) {
		var sig [64]uint8
		err := d.validateReadReplySignature(sig)
		require.Error(t, err)
		require.Contains(t, err.Error(), "zero signature")
	})

	t.Run("non-zero signature", func(t *testing.T) {
		var sig [64]uint8
		sig[0] = 1
		err := d.validateReadReplySignature(sig)
		require.NoError(t, err)
	})
}

func TestValidateSendChannelQueryRequest(t *testing.T) {
	d := newValidationTestDaemon()

	msgID := new([thin.MessageIDLength]byte)
	chanID := uint16(1)
	destHash := new([hash.HashSize]byte)
	queueID := []byte("queue")
	payload := []byte("payload")

	t.Run("valid", func(t *testing.T) {
		req := &Request{
			SendChannelQuery: &thin.SendChannelQuery{
				MessageID:         msgID,
				ChannelID:         &chanID,
				DestinationIdHash: destHash,
				RecipientQueueID:  queueID,
				Payload:           payload,
			},
		}
		require.NoError(t, d.validateSendChannelQueryRequest(req))
	})

	t.Run("nil MessageID", func(t *testing.T) {
		req := &Request{
			SendChannelQuery: &thin.SendChannelQuery{
				ChannelID:         &chanID,
				DestinationIdHash: destHash,
				RecipientQueueID:  queueID,
				Payload:           payload,
			},
		}
		err := d.validateSendChannelQueryRequest(req)
		require.Error(t, err)
		require.Contains(t, err.Error(), "MessageID")
	})

	t.Run("nil ChannelID", func(t *testing.T) {
		req := &Request{
			SendChannelQuery: &thin.SendChannelQuery{
				MessageID:         msgID,
				DestinationIdHash: destHash,
				RecipientQueueID:  queueID,
				Payload:           payload,
			},
		}
		err := d.validateSendChannelQueryRequest(req)
		require.Error(t, err)
		require.Contains(t, err.Error(), "ChannelID")
	})

	t.Run("nil Payload", func(t *testing.T) {
		req := &Request{
			SendChannelQuery: &thin.SendChannelQuery{
				MessageID:         msgID,
				ChannelID:         &chanID,
				DestinationIdHash: destHash,
				RecipientQueueID:  queueID,
			},
		}
		err := d.validateSendChannelQueryRequest(req)
		require.Error(t, err)
		require.Contains(t, err.Error(), "Payload")
	})
}

func TestValidateResumeWriteChannelRequest(t *testing.T) {
	d := newValidationTestDaemon()
	queryID := new([thin.QueryIDLength]byte)

	t.Run("valid", func(t *testing.T) {
		req := &Request{
			ResumeWriteChannel: &thin.ResumeWriteChannel{
				QueryID:  queryID,
				WriteCap: &dummyWriteCap,
			},
		}
		require.NoError(t, d.validateResumeWriteChannelRequest(req))
	})

	t.Run("nil QueryID", func(t *testing.T) {
		req := &Request{
			ResumeWriteChannel: &thin.ResumeWriteChannel{
				WriteCap: &dummyWriteCap,
			},
		}
		require.Error(t, d.validateResumeWriteChannelRequest(req))
	})

	t.Run("nil WriteCap", func(t *testing.T) {
		req := &Request{
			ResumeWriteChannel: &thin.ResumeWriteChannel{
				QueryID: queryID,
			},
		}
		require.Error(t, d.validateResumeWriteChannelRequest(req))
	})
}

func TestValidateResumeReadChannelRequest(t *testing.T) {
	d := newValidationTestDaemon()
	queryID := new([thin.QueryIDLength]byte)

	t.Run("valid", func(t *testing.T) {
		req := &Request{
			ResumeReadChannel: &thin.ResumeReadChannel{
				QueryID: queryID,
				ReadCap: &dummyReadCap,
			},
		}
		require.NoError(t, d.validateResumeReadChannelRequest(req))
	})

	t.Run("nil QueryID", func(t *testing.T) {
		req := &Request{
			ResumeReadChannel: &thin.ResumeReadChannel{
				ReadCap: &dummyReadCap,
			},
		}
		require.Error(t, d.validateResumeReadChannelRequest(req))
	})

	t.Run("nil ReadCap", func(t *testing.T) {
		req := &Request{
			ResumeReadChannel: &thin.ResumeReadChannel{
				QueryID: queryID,
			},
		}
		require.Error(t, d.validateResumeReadChannelRequest(req))
	})
}

func TestValidateResumeWriteChannelQueryRequest(t *testing.T) {
	d := newValidationTestDaemon()
	queryID := new([thin.QueryIDLength]byte)
	envHash := new([32]byte)

	t.Run("valid", func(t *testing.T) {
		req := &Request{
			ResumeWriteChannelQuery: &thin.ResumeWriteChannelQuery{
				QueryID:            queryID,
				WriteCap:           &dummyWriteCap,
				MessageBoxIndex:    &dummyMessageBoxIndex,
				EnvelopeDescriptor: []byte("desc"),
				EnvelopeHash:       envHash,
			},
		}
		require.NoError(t, d.validateResumeWriteChannelQueryRequest(req))
	})

	t.Run("nil QueryID", func(t *testing.T) {
		req := &Request{
			ResumeWriteChannelQuery: &thin.ResumeWriteChannelQuery{
				WriteCap:           &dummyWriteCap,
				MessageBoxIndex:    &dummyMessageBoxIndex,
				EnvelopeDescriptor: []byte("desc"),
				EnvelopeHash:       envHash,
			},
		}
		require.Error(t, d.validateResumeWriteChannelQueryRequest(req))
	})

	t.Run("nil WriteCap", func(t *testing.T) {
		req := &Request{
			ResumeWriteChannelQuery: &thin.ResumeWriteChannelQuery{
				QueryID:            queryID,
				MessageBoxIndex:    &dummyMessageBoxIndex,
				EnvelopeDescriptor: []byte("desc"),
				EnvelopeHash:       envHash,
			},
		}
		require.Error(t, d.validateResumeWriteChannelQueryRequest(req))
	})

	t.Run("nil MessageBoxIndex", func(t *testing.T) {
		req := &Request{
			ResumeWriteChannelQuery: &thin.ResumeWriteChannelQuery{
				QueryID:            queryID,
				WriteCap:           &dummyWriteCap,
				EnvelopeDescriptor: []byte("desc"),
				EnvelopeHash:       envHash,
			},
		}
		require.Error(t, d.validateResumeWriteChannelQueryRequest(req))
	})

	t.Run("nil EnvelopeHash", func(t *testing.T) {
		req := &Request{
			ResumeWriteChannelQuery: &thin.ResumeWriteChannelQuery{
				QueryID:            queryID,
				WriteCap:           &dummyWriteCap,
				MessageBoxIndex:    &dummyMessageBoxIndex,
				EnvelopeDescriptor: []byte("desc"),
			},
		}
		require.Error(t, d.validateResumeWriteChannelQueryRequest(req))
	})
}

func TestValidateResumeReadChannelQueryRequest(t *testing.T) {
	d := newValidationTestDaemon()
	queryID := new([thin.QueryIDLength]byte)
	envHash := new([32]byte)

	t.Run("valid", func(t *testing.T) {
		req := &Request{
			ResumeReadChannelQuery: &thin.ResumeReadChannelQuery{
				QueryID:            queryID,
				ReadCap:            &dummyReadCap,
				NextMessageIndex:   &dummyMessageBoxIndex,
				EnvelopeDescriptor: []byte("desc"),
				EnvelopeHash:       envHash,
			},
		}
		require.NoError(t, d.validateResumeReadChannelQueryRequest(req))
	})

	t.Run("nil QueryID", func(t *testing.T) {
		req := &Request{
			ResumeReadChannelQuery: &thin.ResumeReadChannelQuery{
				ReadCap:            &dummyReadCap,
				NextMessageIndex:   &dummyMessageBoxIndex,
				EnvelopeDescriptor: []byte("desc"),
				EnvelopeHash:       envHash,
			},
		}
		require.Error(t, d.validateResumeReadChannelQueryRequest(req))
	})

	t.Run("nil ReadCap", func(t *testing.T) {
		req := &Request{
			ResumeReadChannelQuery: &thin.ResumeReadChannelQuery{
				QueryID:            queryID,
				NextMessageIndex:   &dummyMessageBoxIndex,
				EnvelopeDescriptor: []byte("desc"),
				EnvelopeHash:       envHash,
			},
		}
		require.Error(t, d.validateResumeReadChannelQueryRequest(req))
	})

	t.Run("nil EnvelopeHash", func(t *testing.T) {
		req := &Request{
			ResumeReadChannelQuery: &thin.ResumeReadChannelQuery{
				QueryID:            queryID,
				ReadCap:            &dummyReadCap,
				NextMessageIndex:   &dummyMessageBoxIndex,
				EnvelopeDescriptor: []byte("desc"),
			},
		}
		require.Error(t, d.validateResumeReadChannelQueryRequest(req))
	})
}

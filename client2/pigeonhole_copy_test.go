// SPDX-FileCopyrightText: Copyright (C) 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package client2

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/client2/thin"
)

func TestValidateStartResendingCopyCommandRequest(t *testing.T) {
	queryID := new([thin.QueryIDLength]byte)

	t.Run("valid", func(t *testing.T) {
		req := &thin.StartResendingCopyCommand{
			QueryID:  queryID,
			WriteCap: &dummyWriteCap,
		}
		require.NoError(t, validateStartResendingCopyCommandRequest(req))
	})

	t.Run("nil QueryID", func(t *testing.T) {
		req := &thin.StartResendingCopyCommand{
			WriteCap: &dummyWriteCap,
		}
		require.Error(t, validateStartResendingCopyCommandRequest(req))
	})

	t.Run("nil WriteCap", func(t *testing.T) {
		req := &thin.StartResendingCopyCommand{
			QueryID: queryID,
		}
		require.Error(t, validateStartResendingCopyCommandRequest(req))
	})
}

func TestValidateCancelResendingCopyCommandRequest(t *testing.T) {
	queryID := new([thin.QueryIDLength]byte)
	writeCapHash := new([32]byte)

	t.Run("valid", func(t *testing.T) {
		req := &thin.CancelResendingCopyCommand{
			QueryID:      queryID,
			WriteCapHash: writeCapHash,
		}
		require.NoError(t, validateCancelResendingCopyCommandRequest(req))
	})

	t.Run("nil QueryID", func(t *testing.T) {
		req := &thin.CancelResendingCopyCommand{
			WriteCapHash: writeCapHash,
		}
		require.Error(t, validateCancelResendingCopyCommandRequest(req))
	})

	t.Run("nil WriteCapHash", func(t *testing.T) {
		req := &thin.CancelResendingCopyCommand{
			QueryID: queryID,
		}
		require.Error(t, validateCancelResendingCopyCommandRequest(req))
	})
}

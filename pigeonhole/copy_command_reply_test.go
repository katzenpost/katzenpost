// SPDX-FileCopyrightText: © 2026 David Stainton
// SPDX-License-Identifier: AGPL-3.0-only

package pigeonhole

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestCopyCommandReplyRoundTrip pins the wire format of CopyCommandReply:
// three fields (Status, ErrorCode, FailedEnvelopeIndex), six bytes
// total, fully round-trippable through MarshalBinary + Parse.
func TestCopyCommandReplyRoundTrip(t *testing.T) {
	cases := []struct {
		name string
		in   CopyCommandReply
	}{
		{
			name: "succeeded",
			in: CopyCommandReply{
				Status:              CopyStatusSucceeded,
				ErrorCode:           0,
				FailedEnvelopeIndex: 0,
			},
		},
		{
			name: "in_progress",
			in: CopyCommandReply{
				Status:              CopyStatusInProgress,
				ErrorCode:           0,
				FailedEnvelopeIndex: 0,
			},
		},
		{
			name: "failed_with_replica_error",
			in: CopyCommandReply{
				Status:              CopyStatusFailed,
				ErrorCode:           ReplicaErrorBoxAlreadyExists,
				FailedEnvelopeIndex: 42,
			},
		},
		{
			name: "failed_large_index",
			in: CopyCommandReply{
				Status:              CopyStatusFailed,
				ErrorCode:           ReplicaErrorInvalidSignature,
				FailedEnvelopeIndex: 0x0102030405060708, // above uint32 range
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			blob, err := tc.in.MarshalBinary()
			require.NoError(t, err)
			require.Len(t, blob, 10, "CopyCommandReply wire size must be 10 bytes")

			out := &CopyCommandReply{}
			remaining, err := out.Parse(blob)
			require.NoError(t, err)
			require.Len(t, remaining, 0, "Parse should consume exactly the 10 bytes")
			require.Equal(t, tc.in.Status, out.Status)
			require.Equal(t, tc.in.ErrorCode, out.ErrorCode)
			require.Equal(t, tc.in.FailedEnvelopeIndex, out.FailedEnvelopeIndex)
		})
	}
}

// TestCopyCommandStatusConstants guards against accidental changes to
// the on-wire values. Changing these numbers would silently break the
// courier<->client daemon protocol.
func TestCopyCommandStatusConstants(t *testing.T) {
	require.Equal(t, uint8(0), CopyStatusSucceeded)
	require.Equal(t, uint8(1), CopyStatusInProgress)
	require.Equal(t, uint8(2), CopyStatusFailed)
}

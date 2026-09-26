// SPDX-License-Identifier: AGPL-3.0-only

package thin

import (
	"fmt"
	"testing"

	signSchemes "github.com/katzenpost/hpqc/sign/schemes"

	"github.com/katzenpost/katzenpost/core/epochtime"
	cpki "github.com/katzenpost/katzenpost/core/pki"
	"github.com/stretchr/testify/require"
)

func TestPureThinClientErrorToString(t *testing.T) {
	cases := []struct {
		name string
		code uint8
		want string
	}{
		{"success", ThinClientSuccess, "Success"},
		{"connection lost", ThinClientErrorConnectionLost, "Connection lost"},
		{"timeout", ThinClientErrorTimeout, "Timeout"},
		{"invalid request", ThinClientErrorInvalidRequest, "Invalid request"},
		{"internal error", ThinClientErrorInternalError, "Internal error"},
		{"max retries", ThinClientErrorMaxRetries, "Maximum retries exceeded"},
		{"invalid channel", ThinClientErrorInvalidChannel, "Invalid channel"},
		{"channel not found", ThinClientErrorChannelNotFound, "Channel not found"},
		{"permission denied", ThinClientErrorPermissionDenied, "Permission denied"},
		{"invalid payload", ThinClientErrorInvalidPayload, "Invalid payload"},
		{"service unavailable", ThinClientErrorServiceUnavailable, "Service unavailable"},
		{"duplicate capability", ThinClientErrorDuplicateCapability, "Duplicate capability"},
		{"courier cache corruption", ThinClientErrorCourierCacheCorruption, "Courier cache corruption"},
		{"propagation error", ThinClientPropagationError, "Propagation error"},
		{"invalid write cap", ThinClientErrorInvalidWriteCapability, "Invalid write capability"},
		{"invalid read cap", ThinClientErrorInvalidReadCapability, "Invalid read capability"},
		{"invalid resume write", ThinClientErrorInvalidResumeWriteChannelRequest, "Invalid resume write channel request"},
		{"invalid resume read", ThinClientErrorInvalidResumeReadChannelRequest, "Invalid resume read channel request"},
		{"impossible hash", ThinClientImpossibleHashError, "Impossible hash error"},
		{"impossible new write cap", ThinClientImpossibleNewWriteCapError, "Failed to create new write capability"},
		{"impossible new stateful writer", ThinClientImpossibleNewStatefulWriterError, "Failed to create new stateful writer"},
		{"capability already in use", ThinClientCapabilityAlreadyInUse, "Capability already in use"},
		{"mkem decryption failed", ThinClientErrorMKEMDecryptionFailed, "MKEM decryption failed"},
		{"bacap decryption failed", ThinClientErrorBACAPDecryptionFailed, "BACAP decryption failed"},
		{"start resending cancelled", ThinClientErrorStartResendingCancelled, "Start resending cancelled"},
		{"invalid tombstone sig", ThinClientErrorInvalidTombstoneSig, "Invalid tombstone signature"},
		{"copy command failed", ThinClientErrorCopyCommandFailed, "Copy command failed"},
		{"payload too large", ThinClientErrorPayloadTooLarge, "Payload too large"},
		{"voucher hash mismatch", ThinClientErrorVoucherHashMismatch, "Voucher payload does not hash to the voucher"},
		{"voucher signature invalid", ThinClientErrorVoucherSignatureInvalid, "Voucher signed please-add did not verify"},
		{"voucher seal open failed", ThinClientErrorVoucherSealOpenFailed, "Voucher sealed reply could not be opened"},
		{"courier invalid envelope", ThinClientErrorCourierInvalidEnvelope, "Courier rejected the envelope as malformed"},
		{"courier invalid epoch", ThinClientErrorCourierInvalidEpoch, "Courier rejected the envelope: replica epoch outside tolerance window"},
		{"unknown just above range", 33, "Unknown thin client error code: 33"},
		{"unknown max", 255, "Unknown thin client error code: 255"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, ThinClientErrorToString(tc.code))
		})
	}
}

func TestPureThinClientErrorCodeToSentinel(t *testing.T) {
	cases := []struct {
		name    string
		code    uint8
		want    error
		wantMsg string
	}{
		{name: "success", code: ThinClientSuccess},
		{name: "mkem", code: ThinClientErrorMKEMDecryptionFailed, want: ErrMKEMDecryptionFailed},
		{name: "bacap", code: ThinClientErrorBACAPDecryptionFailed, want: ErrBACAPDecryptionFailed},
		{name: "cancelled", code: ThinClientErrorStartResendingCancelled, want: ErrStartResendingCancelled},
		{name: "tombstone sig", code: ThinClientErrorInvalidTombstoneSig, want: ErrInvalidTombstoneSignature},
		{name: "copy failed", code: ThinClientErrorCopyCommandFailed, want: ErrCopyCommandFailed},
		{name: "payload too large", code: ThinClientErrorPayloadTooLarge, want: ErrPayloadTooLarge},
		{name: "cache corruption", code: ThinClientErrorCourierCacheCorruption, want: ErrCacheCorruption},
		{name: "propagation", code: ThinClientPropagationError, want: ErrPropagationError},
		{name: "invalid envelope", code: ThinClientErrorCourierInvalidEnvelope, want: ErrInvalidEnvelope},
		{name: "courier invalid epoch", code: ThinClientErrorCourierInvalidEpoch, want: ErrCourierInvalidEpoch},
		{name: "default known string", code: ThinClientErrorTimeout, wantMsg: "Timeout"},
		{name: "default unknown string", code: 200, wantMsg: "Unknown thin client error code: 200"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := thinClientErrorCodeToSentinel(tc.code)
			switch {
			case tc.want != nil:
				require.ErrorIs(t, err, tc.want)
			case tc.wantMsg != "":
				require.Error(t, err)
				require.Equal(t, tc.wantMsg, err.Error())
			default:
				require.NoError(t, err)
			}
		})
	}
}

func TestPureReplicaErrorCodeToSentinel(t *testing.T) {
	cases := []struct {
		name    string
		code    uint8
		want    error
		wantMsg string
	}{
		{name: "success", code: 0},
		{name: "box id not found", code: 1, want: ErrBoxIDNotFound},
		{name: "invalid box id", code: 2, want: ErrInvalidBoxID},
		{name: "invalid signature", code: 3, want: ErrInvalidSignature},
		{name: "database failure", code: 4, want: ErrDatabaseFailure},
		{name: "invalid payload", code: 5, want: ErrInvalidPayload},
		{name: "storage full", code: 6, want: ErrStorageFull},
		{name: "replica internal error", code: 7, want: ErrReplicaInternalError},
		{name: "invalid epoch", code: 8, want: ErrInvalidEpoch},
		{name: "replication failed", code: 9, want: ErrReplicationFailed},
		{name: "box already exists", code: 10, want: ErrBoxAlreadyExists},
		{name: "tombstone", code: 11, want: ErrTombstone},
		{name: "unknown just above range", code: 12, wantMsg: "unknown replica error code: 12"},
		{name: "unknown max", code: 255, wantMsg: "unknown replica error code: 255"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := replicaErrorCodeToSentinel(tc.code)
			switch {
			case tc.want != nil:
				require.ErrorIs(t, err, tc.want)
			case tc.wantMsg != "":
				require.Error(t, err)
				require.Equal(t, tc.wantMsg, err.Error())
			default:
				require.NoError(t, err)
			}
		})
	}
}

func TestPureEventStrings(t *testing.T) {
	pureQueryID := new([QueryIDLength]byte)
	pureZeroQueryIDHex := "00000000000000000000000000000000"

	cases := []struct {
		name  string
		event Event
		want  string
	}{
		{
			name:  "copy command reply with replica error code",
			event: &StartResendingCopyCommandReply{ErrorCode: ThinClientErrorCopyCommandFailed, ReplicaErrorCode: 10, FailedEnvelopeIndex: 3},
			want:  "StartResendingCopyCommandReply (error: Copy command failed, replica error code: 10, failed envelope index: 3)",
		},
		{
			name:  "copy command reply with failed envelope index only",
			event: &StartResendingCopyCommandReply{ErrorCode: ThinClientErrorCopyCommandFailed, FailedEnvelopeIndex: 5},
			want:  "StartResendingCopyCommandReply (error: Copy command failed, replica error code: 0, failed envelope index: 5)",
		},
		{
			name:  "copy command reply with replica error code only",
			event: &StartResendingCopyCommandReply{ErrorCode: ThinClientErrorCopyCommandFailed, ReplicaErrorCode: 11},
			want:  "StartResendingCopyCommandReply (error: Copy command failed, replica error code: 11, failed envelope index: 0)",
		},
		{
			name:  "copy command reply bare error",
			event: &StartResendingCopyCommandReply{ErrorCode: ThinClientErrorTimeout},
			want:  "StartResendingCopyCommandReply (error: Timeout)",
		},
		{
			name:  "copy command reply success",
			event: &StartResendingCopyCommandReply{},
			want:  "StartResendingCopyCommandReply: success",
		},
		{
			name:  "counter reply error",
			event: &GetMessageBoxIndexCounterReply{ErrorCode: ThinClientErrorInternalError, Counter: 7},
			want:  "GetMessageBoxIndexCounterReply (error: Internal error)",
		},
		{
			name:  "counter reply success zero",
			event: &GetMessageBoxIndexCounterReply{},
			want:  "GetMessageBoxIndexCounterReply: counter=0",
		},
		{
			name:  "counter reply success populated",
			event: &GetMessageBoxIndexCounterReply{Counter: 42},
			want:  "GetMessageBoxIndexCounterReply: counter=42",
		},
		{
			name:  "pki document reply error",
			event: &GetPKIDocumentReply{ErrorCode: ThinClientErrorTimeout, Epoch: 9},
			want:  "GetPKIDocumentReply: epoch=9 (error: Timeout)",
		},
		{
			name:  "pki document reply success zero",
			event: &GetPKIDocumentReply{},
			want:  "GetPKIDocumentReply: epoch=0 payloadLen=0",
		},
		{
			name:  "pki document reply success populated",
			event: &GetPKIDocumentReply{Epoch: 123, Payload: []byte("abcd")},
			want:  "GetPKIDocumentReply: epoch=123 payloadLen=4",
		},
		{
			name:  "directory authorities reply error",
			event: &GetDirectoryAuthoritiesReply{ErrorCode: ThinClientErrorServiceUnavailable},
			want:  "GetDirectoryAuthoritiesReply (error: Service unavailable)",
		},
		{
			name:  "directory authorities reply success empty",
			event: &GetDirectoryAuthoritiesReply{},
			want:  "GetDirectoryAuthoritiesReply: 0 authorities",
		},
		{
			name:  "directory authorities reply success populated",
			event: &GetDirectoryAuthoritiesReply{Authorities: []*DirectoryAuthority{{Identifier: "auth1"}, {Identifier: "auth2"}}},
			want:  "GetDirectoryAuthoritiesReply: 2 authorities",
		},
		{
			name:  "tombstone range reply error",
			event: &CreateCourierEnvelopesFromTombstoneRangeReply{QueryID: pureQueryID, ErrorCode: ThinClientErrorInvalidRequest},
			want:  "CreateCourierEnvelopesFromTombstoneRangeReply: queryID=" + pureZeroQueryIDHex + " (error: Invalid request)",
		},
		{
			name:  "tombstone range reply success empty",
			event: &CreateCourierEnvelopesFromTombstoneRangeReply{QueryID: pureQueryID},
			want:  "CreateCourierEnvelopesFromTombstoneRangeReply: queryID=" + pureZeroQueryIDHex + " numEnvelopes=0 bufferLen=0",
		},
		{
			name:  "tombstone range reply success populated",
			event: &CreateCourierEnvelopesFromTombstoneRangeReply{QueryID: pureQueryID, Envelopes: [][]byte{{1}, {2}}, Buffer: []byte("xyz")},
			want:  "CreateCourierEnvelopesFromTombstoneRangeReply: queryID=" + pureZeroQueryIDHex + " numEnvelopes=2 bufferLen=3",
		},
		{
			name:  "voucher mint reply error",
			event: &VoucherMintReply{ErrorCode: ThinClientErrorVoucherHashMismatch},
			want:  "VoucherMintReply (error: Voucher payload does not hash to the voucher)",
		},
		{
			name:  "voucher mint reply success",
			event: &VoucherMintReply{Voucher: []byte("v")},
			want:  "VoucherMintReply: success",
		},
		{
			name:  "voucher induct reply error",
			event: &VoucherInductReply{ErrorCode: ThinClientErrorVoucherSignatureInvalid},
			want:  "VoucherInductReply (error: Voucher signed please-add did not verify)",
		},
		{
			name:  "voucher induct reply success",
			event: &VoucherInductReply{DisplayName: "alice"},
			want:  "VoucherInductReply: success",
		},
		{
			name:  "voucher open reply error",
			event: &VoucherOpenReply{ErrorCode: ThinClientErrorVoucherSealOpenFailed},
			want:  "VoucherOpenReply (error: Voucher sealed reply could not be opened)",
		},
		{
			name:  "voucher open reply success",
			event: &VoucherOpenReply{Salt: []byte("s")},
			want:  "VoucherOpenReply: success",
		},
		{
			name:  "voucher derive stream reply error",
			event: &VoucherDeriveStreamReply{ErrorCode: 200},
			want:  "VoucherDeriveStreamReply (error: Unknown thin client error code: 200)",
		},
		{
			name:  "voucher derive stream reply success",
			event: &VoucherDeriveStreamReply{VoucherReadCap: []byte("r")},
			want:  "VoucherDeriveStreamReply: success",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, tc.want, tc.event.String())
		})
	}
}

func TestPureNewPKIDocumentEventStringPanics(t *testing.T) {
	cases := []struct {
		name    string
		payload []byte
	}{
		{name: "nil payload", payload: nil},
		{name: "empty payload", payload: []byte{}},
		{name: "not a certificate", payload: []byte("not a document")},
		{name: "truncated cbor", payload: []byte{0xa1, 0x01}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			e := &NewPKIDocumentEvent{Payload: tc.payload}
			require.Panics(t, func() {
				_ = e.String()
			})
		})
	}
}

func TestPureNewPKIDocumentEventStringSignedDocument(t *testing.T) {
	scheme := signSchemes.ByName("Ed25519")
	pubKey, privKey, err := scheme.GenerateKey()
	require.NoError(t, err)

	epoch, _, _ := epochtime.Now()
	payload, err := cpki.SignDocument(privKey, pubKey, &cpki.Document{
		Epoch:              epoch,
		PKISignatureScheme: "Ed25519",
	})
	require.NoError(t, err)

	e := &NewPKIDocumentEvent{Payload: payload}
	require.Equal(t, fmt.Sprintf("PKI Document for epoch %d", epoch), e.String())
}

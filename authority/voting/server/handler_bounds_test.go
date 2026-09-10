// SPDX-FileCopyrightText: © 2026 Jacob Appelbaum
// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/hash"

	"github.com/katzenpost/katzenpost/core/cert"
	"github.com/katzenpost/katzenpost/core/wire/commands"
)

// The authority upload handlers accept a signed, opaque payload from an
// authorized peer. These tests assert that a validly signed but structurally
// garbage payload is rejected with an error status rather than panicking, so a
// single authority cannot crash its peers by uploading malformed content.

func TestOnVoteUploadGarbagePayloadRejected(t *testing.T) {
	require := require.New(t)
	st, key, votingEpoch := newSingleAuthorityState(t)
	signed, err := cert.Sign(key.idKey, key.idPubKey, []byte("not-a-document"), votingEpoch+100)
	require.NoError(err)
	vote := &commands.Vote{Epoch: votingEpoch, PublicKey: key.idPubKey, Payload: signed}

	var resp commands.Command
	require.NotPanics(func() { resp = st.onVoteUpload(vote) })
	vs, ok := resp.(*commands.VoteStatus)
	require.True(ok, "expected *VoteStatus, got %T", resp)
	require.True(vs.ErrorCode != commands.VoteOk, "garbage vote must be rejected, got %d", vs.ErrorCode)
}

func TestOnCertUploadGarbagePayloadRejected(t *testing.T) {
	require := require.New(t)
	st, key, votingEpoch := newSingleAuthorityState(t)
	signed, err := cert.Sign(key.idKey, key.idPubKey, []byte("not-a-document"), votingEpoch+100)
	require.NoError(err)
	c := &commands.Cert{Epoch: votingEpoch, PublicKey: key.idPubKey, Payload: signed}
	keyHash := hash.Sum256From(key.idPubKey)

	var resp commands.Command
	require.NotPanics(func() { resp = st.onCertUpload(c, keyHash[:]) })
	cs, ok := resp.(*commands.CertStatus)
	require.True(ok, "expected *CertStatus, got %T", resp)
	require.True(cs.ErrorCode != commands.CertOk, "garbage cert must be rejected, got %d", cs.ErrorCode)
}

func TestOnSigUploadGarbagePayloadRejected(t *testing.T) {
	require := require.New(t)
	st, key, votingEpoch := newSingleAuthorityState(t)
	signed, err := cert.Sign(key.idKey, key.idPubKey, []byte("not-a-signature"), votingEpoch+100)
	require.NoError(err)
	sig := &commands.Sig{Epoch: votingEpoch, PublicKey: key.idPubKey, Payload: signed}

	var resp commands.Command
	require.NotPanics(func() { resp = st.onSigUpload(sig) })
	ss, ok := resp.(*commands.SigStatus)
	require.True(ok, "expected *SigStatus, got %T", resp)
	require.True(ss.ErrorCode != commands.SigOk, "garbage sig must be rejected, got %d", ss.ErrorCode)
}

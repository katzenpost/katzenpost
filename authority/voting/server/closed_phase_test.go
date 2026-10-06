// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/hash"

	"github.com/katzenpost/katzenpost/core/wire/commands"
)

func TestPeerMessagesForAClosedPhaseAreTooLate(t *testing.T) {
	st, key, votingEpoch := newSingleAuthorityState(t)
	pk := hash.Sum256From(key.idPubKey)
	vote := func() uint8 {
		return st.onVoteUpload(&commands.Vote{Epoch: votingEpoch, PublicKey: key.idPubKey, Payload: []byte{1}}, pk[:]).(*commands.VoteStatus).ErrorCode
	}
	certificate := func() uint8 {
		return st.onCertUpload(&commands.Cert{Epoch: votingEpoch, PublicKey: key.idPubKey, Payload: []byte{1}}, pk[:]).(*commands.CertStatus).ErrorCode
	}
	reveal := func() uint8 {
		return st.onRevealUpload(signedReveal(t, key, votingEpoch, epochToBytes(votingEpoch)), pk[:]).(*commands.RevealStatus).ErrorCode
	}

	st.state = stateAcceptReveal
	require.EqualValues(t, commands.RevealTooEarly, reveal())
	require.EqualValues(t, commands.VoteNotSigned, vote())
	require.EqualValues(t, commands.CertNotSigned, certificate())

	st.state = stateAcceptCert
	require.EqualValues(t, commands.RevealTooLate, reveal())
	require.EqualValues(t, commands.VoteTooLate, vote())
	require.EqualValues(t, commands.CertNotSigned, certificate())

	st.state = stateAcceptSignature
	require.EqualValues(t, commands.RevealTooLate, reveal())
	require.EqualValues(t, commands.VoteTooLate, vote())
	require.EqualValues(t, commands.CertTooLate, certificate())
}

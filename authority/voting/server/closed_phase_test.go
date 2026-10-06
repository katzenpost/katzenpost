// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/hash"

	"github.com/katzenpost/katzenpost/core/pki"
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
	require.EqualValues(t, commands.VoteNotSigned, vote())
	require.EqualValues(t, commands.CertNotSigned, certificate())

	st.state = stateAcceptSignature
	require.EqualValues(t, commands.RevealTooLate, reveal())
	require.EqualValues(t, commands.VoteTooLate, vote())
	require.EqualValues(t, commands.CertTooLate, certificate())
}

func TestRetriedPeerMessageAfterItsPhaseIsAlreadyReceived(t *testing.T) {
	st, key, votingEpoch := newSingleAuthorityState(t)
	pk := hash.Sum256From(key.idPubKey)
	st.votes[votingEpoch] = map[[publicKeyHashSize]byte]*pki.Document{pk: new(pki.Document)}
	st.certificates[votingEpoch] = map[[publicKeyHashSize]byte]*pki.Document{pk: new(pki.Document)}
	st.reveals[votingEpoch] = map[[publicKeyHashSize]byte][]byte{pk: {1}}

	st.state = stateAcceptSignature
	vote := st.onVoteUpload(&commands.Vote{Epoch: votingEpoch, PublicKey: key.idPubKey, Payload: []byte{1}}, pk[:]).(*commands.VoteStatus).ErrorCode
	require.EqualValues(t, commands.VoteAlreadyReceived, vote)
	certificate := st.onCertUpload(&commands.Cert{Epoch: votingEpoch, PublicKey: key.idPubKey, Payload: []byte{1}}, pk[:]).(*commands.CertStatus).ErrorCode
	require.EqualValues(t, commands.CertAlreadyReceived, certificate)
	reveal := st.onRevealUpload(signedReveal(t, key, votingEpoch, epochToBytes(votingEpoch)), pk[:]).(*commands.RevealStatus).ErrorCode
	require.EqualValues(t, commands.RevealAlreadyReceived, reveal)

	st.state = stateAcceptCert
	reveal = st.onRevealUpload(signedReveal(t, key, votingEpoch, epochToBytes(votingEpoch)), pk[:]).(*commands.RevealStatus).ErrorCode
	require.EqualValues(t, commands.RevealAlreadyReceived, reveal)
}

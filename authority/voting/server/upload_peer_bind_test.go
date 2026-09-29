// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/hash"
	"github.com/katzenpost/hpqc/sign"
	signSchemes "github.com/katzenpost/hpqc/sign/schemes"

	"github.com/katzenpost/katzenpost/core/cert"
	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/wire/commands"
)

// twoAuthorityState builds a state with two authorized authorities: the
// connected peer and the "other" authority whose key an upload will falsely
// declare. It returns the state, the other authority's key material, and the
// peer's identity hash to pass as the wire-authenticated peer.
func twoAuthorityState(t *testing.T) (st *state, otherPub sign.PublicKey, otherPriv sign.PrivateKey, peerHash [publicKeyHashSize]byte, votingEpoch uint64) {
	t.Helper()
	ss := signSchemes.ByName("Ed25519")
	require.NotNil(t, ss)

	peerPub, _, err := ss.GenerateKey()
	require.NoError(t, err)
	otherPub, otherPriv, err = ss.GenerateKey()
	require.NoError(t, err)

	peerHash = hash.Sum256From(peerPub)
	otherHash := hash.Sum256From(otherPub)

	backend, err := log.New(filepath.Join(t.TempDir(), "test.log"), "ERROR", false)
	require.NoError(t, err)
	t.Cleanup(func() { _ = backend.Close() })

	votingEpoch, _, _ = epochtime.Now()
	st = &state{
		log: backend.GetLogger("upload-peer-bind"),
		authorizedAuthorities: map[[publicKeyHashSize]byte]bool{
			peerHash:  true,
			otherHash: true,
		},
		authorityNames: map[[publicKeyHashSize]byte]string{
			peerHash:  "peer",
			otherHash: "other",
		},
		votingEpoch:  votingEpoch,
		votes:        map[uint64]map[[publicKeyHashSize]byte]*pki.Document{},
		commits:      map[uint64]map[[publicKeyHashSize]byte][]byte{},
		reveals:      map[uint64]map[[publicKeyHashSize]byte][]byte{},
		signatures:   map[uint64]map[[publicKeyHashSize]byte]*cert.Signature{},
		certificates: map[uint64]map[[publicKeyHashSize]byte]*pki.Document{},
	}
	return st, otherPub, otherPriv, peerHash, votingEpoch
}

// onVoteUpload must bind the vote's declared PublicKey to the wire-authenticated
// peer, so an authorized but byzantine authority cannot relay another
// authority's vote on its own connection.
func TestOnVoteUploadRejectsForeignPeerKey(t *testing.T) {
	st, otherPub, otherPriv, peerHash, votingEpoch := twoAuthorityState(t)

	doc := &pki.Document{
		Epoch:              votingEpoch,
		GenesisEpoch:       votingEpoch,
		PKISignatureScheme: "Ed25519",
	}
	signed, err := pki.SignDocument(otherPriv, otherPub, doc)
	require.NoError(t, err)

	resp := st.onVoteUpload(&commands.Vote{
		Epoch:     votingEpoch,
		PublicKey: otherPub,
		Payload:   signed,
	}, peerHash[:])
	status, ok := resp.(*commands.VoteStatus)
	require.True(t, ok, "onVoteUpload must return a *VoteStatus")
	require.EqualValues(t, commands.VoteNotAuthorized, status.ErrorCode,
		"a vote whose PublicKey is a different authority than the connected peer must be rejected")
}

// onRevealUpload must bind the reveal's declared PublicKey to the connected peer.
func TestOnRevealUploadRejectsForeignPeerKey(t *testing.T) {
	st, otherPub, otherPriv, peerHash, votingEpoch := twoAuthorityState(t)

	signed, err := cert.Sign(otherPriv, otherPub, epochToBytes(votingEpoch), votingEpoch+100)
	require.NoError(t, err)

	resp := st.onRevealUpload(&commands.Reveal{
		Epoch:     votingEpoch,
		PublicKey: otherPub,
		Payload:   signed,
	}, peerHash[:])
	status, ok := resp.(*commands.RevealStatus)
	require.True(t, ok, "onRevealUpload must return a *RevealStatus")
	require.EqualValues(t, commands.RevealNotAuthorized, status.ErrorCode,
		"a reveal whose PublicKey is a different authority than the connected peer must be rejected")
}

// onSigUpload must bind the signature's declared PublicKey to the connected peer.
func TestOnSigUploadRejectsForeignPeerKey(t *testing.T) {
	st, otherPub, otherPriv, peerHash, votingEpoch := twoAuthorityState(t)

	signed, err := cert.Sign(otherPriv, otherPub, []byte("a-signature"), votingEpoch+100)
	require.NoError(t, err)

	resp := st.onSigUpload(&commands.Sig{
		Epoch:     votingEpoch,
		PublicKey: otherPub,
		Payload:   signed,
	}, peerHash[:])
	status, ok := resp.(*commands.SigStatus)
	require.True(t, ok, "onSigUpload must return a *SigStatus")
	require.EqualValues(t, commands.SigNotAuthorized, status.ErrorCode,
		"a sig whose PublicKey is a different authority than the connected peer must be rejected")
}

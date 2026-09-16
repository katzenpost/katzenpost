// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/hash"

	"github.com/katzenpost/katzenpost/authority/voting/server/config"
	"github.com/katzenpost/katzenpost/core/cert"
	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/wire/commands"
)

// newSingleAuthorityState builds a minimal state with one authorized authority,
// enough to drive the authority upload handlers directly.
func newSingleAuthorityState(t *testing.T) (*state, peerKeys, uint64) {
	t.Helper()
	require := require.New(t)

	params := &config.Parameters{Mu: 0.001, LambdaP: 0.002, LambdaL: 0.0005, LambdaM: 0.2}
	keys, authCfgs, err := genVotingAuthoritiesCfg(params, 1)
	require.NoError(err)

	votingEpoch, _, _ := epochtime.Now()
	votingEpoch += 5

	st := new(state)
	st.votingEpoch = votingEpoch
	st.authorizedAuthorities = make(map[[publicKeyHashSize]byte]bool)
	st.authorityNames = make(map[[publicKeyHashSize]byte]string)
	// Mirror the per-epoch maps that newState() initializes in production, so
	// the handlers do not assign into a nil map.
	st.votes = make(map[uint64]map[[publicKeyHashSize]byte]*pki.Document)
	st.certificates = make(map[uint64]map[[publicKeyHashSize]byte]*pki.Document)
	st.reveals = make(map[uint64]map[[publicKeyHashSize]byte][]byte)
	st.signatures = make(map[uint64]map[[publicKeyHashSize]byte]*cert.Signature)
	st.commits = make(map[uint64]map[[publicKeyHashSize]byte][]byte)
	pk := hash.Sum256From(keys[0].idPubKey)
	st.authorizedAuthorities[pk] = true
	st.authorityNames[pk] = "auth0"

	s := &Server{
		cfg:                authCfgs[0],
		identityPrivateKey: keys[0].idKey,
		identityPublicKey:  keys[0].idPubKey,
		fatalErrCh:         make(chan error, 1),
		haltedCh:           make(chan interface{}),
	}
	st.s = s
	lb, err := log.New("", "DEBUG", false)
	require.NoError(err)
	s.logBackend = lb
	st.log = lb.GetLogger("reveal-bounds-test")

	return st, keys[0], votingEpoch
}

// signedReveal returns a validly signed reveal command whose certified payload
// is exactly payload, i.e. the caller controls its length.
func signedReveal(t *testing.T, key peerKeys, votingEpoch uint64, payload []byte) *commands.Reveal {
	t.Helper()
	signed, err := cert.Sign(key.idKey, key.idPubKey, payload, votingEpoch+100)
	require.NoError(t, err)
	return &commands.Reveal{
		Epoch:     votingEpoch,
		PublicKey: key.idPubKey,
		Payload:   signed,
	}
}

// TestOnRevealUploadShortCertifiedDoesNotPanic is the regression for the
// slice-bounds panic: onRevealUpload read certified[:8] as the epoch without
// checking the length, so a validly signed reveal whose certified body is
// shorter than the 8-byte epoch prefix crashed the authority. It must be
// rejected instead.
func TestOnRevealUploadShortCertifiedDoesNotPanic(t *testing.T) {
	require := require.New(t)
	for _, n := range []int{1, 7} {
		st, key, votingEpoch := newSingleAuthorityState(t)
		reveal := signedReveal(t, key, votingEpoch, make([]byte, n))
		keyHash := hash.Sum256From(key.idPubKey)

		var resp commands.Command
		require.NotPanics(func() { resp = st.onRevealUpload(reveal, keyHash[:]) },
			"onRevealUpload panicked on a %d-byte certified reveal", n)
		rs, ok := resp.(*commands.RevealStatus)
		require.True(ok, "expected *RevealStatus, got %T", resp)
		require.True(rs.ErrorCode == commands.RevealNotSigned,
			"a %d-byte certified reveal must be rejected, got code %d", n, rs.ErrorCode)
	}
}

// TestOnRevealUploadEightByteCertifiedIsHandled is the boundary case: a reveal
// whose certified body is exactly the 8-byte epoch prefix passes the length
// check and is handled by the normal epoch logic, without panicking.
func TestOnRevealUploadEightByteCertifiedIsHandled(t *testing.T) {
	require := require.New(t)
	st, key, votingEpoch := newSingleAuthorityState(t)
	reveal := signedReveal(t, key, votingEpoch, make([]byte, 8))
	keyHash := hash.Sum256From(key.idPubKey)

	var resp commands.Command
	require.NotPanics(func() { resp = st.onRevealUpload(reveal, keyHash[:]) })
	_, ok := resp.(*commands.RevealStatus)
	require.True(ok, "expected *RevealStatus, got %T", resp)
}

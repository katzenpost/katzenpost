// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/hash"

	"github.com/katzenpost/katzenpost/authority/voting/server/config"
	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/pki"
)

func exchangeNoticeVotes(t *testing.T, notices []config.Notice) ([]*state, uint64) {
	epoch, _, _ := epochtime.Now()
	epoch++
	states, _ := buildScenarioStates(t, len(notices), epoch, nil)
	for i, s := range states {
		s.s.cfg.Notice = notices[i]
		s.votingEpoch = epoch
		s.genesisEpoch = epoch
	}
	for i, s := range states {
		vote, err := s.getVote(epoch)
		require.NoError(t, err)
		for j, a := range states {
			if j != i {
				a.Lock()
				a.votes[epoch][hash.Sum256From(s.s.identityPublicKey)] = vote
				a.Unlock()
			}
		}
	}
	return states, epoch
}

func runNoticeRound(t *testing.T, notices []config.Notice) ([]*pki.Document, []error) {
	states, epoch := exchangeNoticeVotes(t, notices)
	for i, s := range states {
		s.state = stateAcceptReveal
		r := s.reveal(epoch)
		for j, a := range states {
			if j != i {
				a.Lock()
				a.reveals[epoch][hash.Sum256From(s.s.identityPublicKey)] = r
				a.Unlock()
			}
		}
	}
	for i, s := range states {
		s.Lock()
		s.state = stateAcceptCert
		c, err := s.getCertificate(epoch)
		require.NoError(t, err)
		_, err = pki.SignDocument(s.s.identityPrivateKey, s.s.identityPublicKey, c)
		require.NoError(t, err)
		s.Unlock()
		for j, a := range states {
			if j != i {
				a.Lock()
				a.certificates[epoch][hash.Sum256From(s.s.identityPublicKey)] = c
				a.Unlock()
			}
		}
	}
	for _, s := range states {
		s.Lock()
		_, err := s.getMyConsensus(epoch)
		s.Unlock()
		require.NoError(t, err)
	}
	for i, s := range states {
		s.state = stateAcceptSignature
		sig := s.myconsensus[epoch].Signatures[hash.Sum256From(s.s.identityPublicKey)]
		for j, a := range states {
			if j != i {
				a.Lock()
				a.signatures[epoch][hash.Sum256From(s.s.identityPublicKey)] = &sig
				a.Unlock()
			}
		}
	}
	docs := make([]*pki.Document, len(states))
	errs := make([]error, len(states))
	for i, s := range states {
		s.Lock()
		docs[i], errs[i] = s.getThresholdConsensus(epoch)
		s.Unlock()
	}
	return docs, errs
}

func TestConsensusCarriesAgreedNotice(t *testing.T) {
	n := config.Notice{MinClientVersion: "v0.0.105", ClientNotice: "upgrade soon"}
	docs, errs := runNoticeRound(t, []config.Notice{n, n, n})
	for i := range docs {
		require.NoError(t, errs[i])
		require.Equal(t, "v0.0.105", docs[i].MinClientVersion)
		require.Equal(t, "upgrade soon", docs[i].ClientNotice)
	}
}

func TestMismatchedNoticesFormNoConsensus(t *testing.T) {
	states, epoch := exchangeNoticeVotes(t, []config.Notice{{ClientNotice: "a"}, {ClientNotice: "b"}, {ClientNotice: "c"}})
	for _, s := range states {
		s.Lock()
		_, _, _, err := s.tallyVotes(epoch)
		s.Unlock()
		require.Error(t, err)
	}
}

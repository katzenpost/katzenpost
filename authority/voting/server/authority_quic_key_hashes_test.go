// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"bytes"
	"fmt"
	"reflect"
	"testing"

	"github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/hash"

	"github.com/katzenpost/katzenpost/core/cert"
	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/wire/commands"
	"github.com/katzenpost/katzenpost/quic/common"
)

const authorityQUICKeyHashesKey = "AuthorityQUICKeyHashes"

func optInQUICKeyHashes(t *testing.T, s *state, votingEpoch uint64) {
	t.Helper()
	cfg := *s.s.cfg
	server := *cfg.Server
	server.PublishQUICKeyHashes = true
	server.Addresses = append(append([]string{}, server.Addresses...), "quic://127.0.0.1:1")
	cfg.Server = &server
	s.s.cfg = &cfg
	keys, err := common.NewEpochKeys(t.TempDir(), func() uint64 { return votingEpoch - 1 })
	require.NoError(t, err)
	s.s.quicKeys = keys
}

func certifiedFields(t *testing.T, signed []byte) map[string]cbor.RawMessage {
	t.Helper()
	payload, err := cert.GetCertified(signed)
	require.NoError(t, err)
	var fields map[string]cbor.RawMessage
	require.NoError(t, cbor.Unmarshal(payload, &fields))
	return fields
}

func TestVoteCarriesItsOwnQUICKeyHashes(t *testing.T) {
	epoch, _, _ := epochtime.Now()
	epoch += 1
	states, _ := buildScenarioStates(t, 3, epoch, nil)
	t.Cleanup(func() {
		for _, s := range states {
			close(s.s.haltedCh)
			s.db.Close()
		}
	})
	s := states[0]
	s.genesisEpoch = epoch
	optInQUICKeyHashes(t, s, epoch)
	vote, err := s.getVote(epoch)
	require.NoError(t, err)
	raw, err := vote.MarshalCertificate()
	require.NoError(t, err)
	encoded, ok := certifiedFields(t, raw)[authorityQUICKeyHashesKey]
	require.True(t, ok, "an opted-in authority's vote carries no AuthorityQUICKeyHashes")
	var entries map[[publicKeyHashSize]byte][]byte
	require.NoError(t, cbor.Unmarshal(encoded, &entries))
	want, err := s.s.quicKeys.Hashes(epoch)
	require.NoError(t, err)
	require.Equal(t, map[[publicKeyHashSize]byte][]byte{hash.Sum256From(s.s.identityPublicKey): want}, entries)
}

func TestOptedInTCPAuthorityVotesItsQUICKeyHashes(t *testing.T) {
	epoch, _, _ := epochtime.Now()
	epoch += 1
	states, _ := buildScenarioStates(t, 3, epoch, nil)
	t.Cleanup(func() {
		for _, s := range states {
			close(s.s.haltedCh)
			s.db.Close()
		}
	})
	s := states[0]
	s.genesisEpoch = epoch
	optInQUICKeyHashes(t, s, epoch)
	s.s.cfg.Server.Addresses = s.s.cfg.Server.Addresses[:len(s.s.cfg.Server.Addresses)-1]
	vote, err := s.getVote(epoch)
	require.NoError(t, err)
	raw, err := vote.MarshalCertificate()
	require.NoError(t, err)
	_, ok := certifiedFields(t, raw)[authorityQUICKeyHashesKey]
	require.True(t, ok, "an opted-in authority without a quic address votes no AuthorityQUICKeyHashes, so a TCP+QUIC network never carries them")
}

func TestConsensusCarriesAuthorityQUICKeyHashesOnlyFromEveryAuthority(t *testing.T) {
	for _, n := range []int{3, 4, 5} {
		for _, optedIn := range []int{n, n - 1, 1, 0} {
			t.Run(fmt.Sprintf("%d of %d", optedIn, n), func(t *testing.T) {
				epoch, _, _ := epochtime.Now()
				epoch += 1
				want := make(map[[publicKeyHashSize]byte][]byte)
				docs := runVoteScenarioWith(t, n, epoch, nil, func(states []*state) {
					for _, s := range states[:optedIn] {
						optInQUICKeyHashes(t, s, epoch)
						h, err := s.s.quicKeys.Hashes(epoch)
						require.NoError(t, err)
						want[hash.Sum256From(s.s.identityPublicKey)] = h
					}
				})
				for i, doc := range docs {
					raw, err := doc.MarshalCertificate()
					require.NoError(t, err)
					encoded, ok := certifiedFields(t, raw)[authorityQUICKeyHashesKey]
					if optedIn < n {
						require.False(t, ok, "authority %d: a consensus from %d of %d opted-in authorities carries AuthorityQUICKeyHashes", i, optedIn, n)
						continue
					}
					require.True(t, ok, "authority %d: a consensus from %d of %d opted-in authorities carries no AuthorityQUICKeyHashes", i, optedIn, n)
					var got map[[publicKeyHashSize]byte][]byte
					require.NoError(t, cbor.Unmarshal(encoded, &got))
					require.Equal(t, want, got, "authority %d", i)
				}
			})
		}
	}
}

func TestVoteWithForeignQUICKeyHashesIsMalformed(t *testing.T) {
	epoch, _, _ := epochtime.Now()
	epoch += 1
	states, _ := buildScenarioStates(t, 3, epoch, nil)
	t.Cleanup(func() {
		for _, s := range states {
			close(s.s.haltedCh)
			s.db.Close()
		}
	})
	for _, s := range states {
		s.genesisEpoch = epoch
		s.votingEpoch = epoch
		s.state = stateAcceptVote
	}
	from, other, target := states[0], states[1], states[2]
	self := hash.Sum256From(from.s.identityPublicKey)
	foreign := hash.Sum256From(other.s.identityPublicKey)
	h := make([]byte, 3*pki.QUICKeyHashSize)
	cases := map[string]map[[publicKeyHashSize]byte][]byte{
		"another authority's entry": {foreign: h},
		"two entries":               {self: h, foreign: h},
	}
	for name, entries := range cases {
		t.Run(name, func(t *testing.T) {
			vote, err := from.getVote(epoch)
			require.NoError(t, err)
			delete(from.votes[epoch], self)
			vote.AuthorityQUICKeyHashes = entries
			vote.Signatures = nil
			raw, err := pki.SignDocument(from.s.identityPrivateKey, from.s.identityPublicKey, vote)
			require.NoError(t, err)
			delete(target.votes[epoch], self)
			resp := target.onVoteUpload(&commands.Vote{Epoch: epoch, PublicKey: from.s.identityPublicKey, Payload: raw}, self[:]).(*commands.VoteStatus)
			require.Equal(t, uint8(commands.VoteMalformed), resp.ErrorCode, "%s: a vote naming QUIC key hashes it does not own was accepted", name)
		})
	}
}

func preAuthorityQUICKeyHashesDocumentType() reflect.Type {
	current := reflect.TypeOf(pki.Document{})
	fields := make([]reflect.StructField, 0, current.NumField())
	for i := 0; i < current.NumField(); i++ {
		if f := current.Field(i); f.Name != authorityQUICKeyHashesKey {
			fields = append(fields, f)
		}
	}
	return reflect.StructOf(fields)
}

func reencodedByPreAuthorityQUICKeyHashesCode(t *testing.T, payload []byte) []byte {
	t.Helper()
	old := reflect.New(preAuthorityQUICKeyHashesDocumentType())
	require.NoError(t, cbor.Unmarshal(payload, old.Interface()))
	em, err := cbor.CanonicalEncOptions().EncMode()
	require.NoError(t, err)
	b, err := em.Marshal(old.Interface())
	require.NoError(t, err)
	return b
}

func TestConsensusWithoutEveryAuthorityIsUnchangedForOldAuthorities(t *testing.T) {
	for _, n := range []int{3, 4} {
		for _, optedIn := range []int{n, n - 1, 0} {
			t.Run(fmt.Sprintf("%d of %d", optedIn, n), func(t *testing.T) {
				epoch, _, _ := epochtime.Now()
				epoch += 1
				docs := runVoteScenarioWith(t, n, epoch, nil, func(states []*state) {
					for _, s := range states[:optedIn] {
						optInQUICKeyHashes(t, s, epoch)
					}
				})
				for i, doc := range docs {
					raw, err := doc.MarshalCertificate()
					require.NoError(t, err)
					payload, err := cert.GetCertified(raw)
					require.NoError(t, err)
					unchanged := bytes.Equal(payload, reencodedByPreAuthorityQUICKeyHashesCode(t, payload))
					if optedIn == n {
						require.False(t, unchanged, "authority %d: an old authority would re-encode an all-opted-in consensus unchanged", i)
						continue
					}
					require.True(t, unchanged, "authority %d: an old authority re-encodes a consensus from %d of %d opted-in authorities differently", i, optedIn, n)
				}
			})
		}
	}
}

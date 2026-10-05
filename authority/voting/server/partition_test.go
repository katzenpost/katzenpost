// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/katzenpost/hpqc/hash"
	"github.com/katzenpost/hpqc/rand"
	signSchemes "github.com/katzenpost/hpqc/sign/schemes"
	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/authority/voting/server/config"
	"github.com/katzenpost/katzenpost/core/cert"
	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/wire"
	"github.com/katzenpost/katzenpost/core/wire/commands"
)

func partitionCode(t *testing.T, resp commands.Command) uint8 {
	switch r := resp.(type) {
	case *commands.VoteStatus:
		return r.ErrorCode
	case *commands.RevealStatus:
		return r.ErrorCode
	case *commands.CertStatus:
		return r.ErrorCode
	case *commands.SigStatus:
		return r.ErrorCode
	}
	t.Fatalf("unexpected response %T", resp)
	return 0
}

func runPartitionedRound(t *testing.T, authNum int, groups [][]int) ([]*state, []*config.Config, uint64, map[int]*pki.Document) {
	require := require.New(t)
	epoch, _, _ := epochtime.Now()
	epoch += 2
	states, cfgs := buildScenarioStates(t, authNum, epoch, nil)
	pkOf := func(s *state) [publicKeyHashSize]byte { return hash.Sum256From(s.s.identityPublicKey) }
	for _, s := range states {
		s.votingEpoch, s.genesisEpoch = epoch, epoch
		s.commits = map[uint64]map[[publicKeyHashSize]byte][]byte{}
		s.reveals = map[uint64]map[[publicKeyHashSize]byte][]byte{}
	}
	each := func(f func(from, to *state)) {
		for _, g := range groups {
			for _, i := range g {
				for _, j := range g {
					if i != j {
						f(states[i], states[j])
					}
				}
			}
		}
	}

	votes := map[*state][]byte{}
	for _, s := range states {
		s.state = stateAcceptVote
		v, err := s.getVote(epoch)
		require.NoError(err)
		votes[s], err = v.MarshalCertificate()
		require.NoError(err)
	}
	each(func(from, to *state) {
		fpk := pkOf(from)
		require.EqualValues(commands.VoteOk, partitionCode(t, to.onVoteUpload(&commands.Vote{Epoch: epoch, PublicKey: from.s.identityPublicKey, Payload: votes[from]}, fpk[:])))
	})

	for _, s := range states {
		s.state = stateAcceptReveal
	}
	each(func(from, to *state) {
		fpk := pkOf(from)
		require.EqualValues(commands.RevealOk, partitionCode(t, to.onRevealUpload(&commands.Reveal{Epoch: epoch, PublicKey: from.s.identityPublicKey, Payload: from.reveal(epoch)}, fpk[:])))
	})

	for _, s := range states {
		s.state = stateAcceptCert
	}
	certs := map[*state][]byte{}
	for _, s := range states {
		s.Lock()
		c, err := s.getCertificate(epoch)
		s.Unlock()
		if err != nil {
			continue
		}
		certs[s], err = c.MarshalCertificate()
		require.NoError(err)
	}
	each(func(from, to *state) {
		if raw, ok := certs[from]; ok {
			fpk := pkOf(from)
			to.onCertUpload(&commands.Cert{Epoch: epoch, PublicKey: from.s.identityPublicKey, Payload: raw}, fpk[:])
		}
	})

	for _, s := range states {
		s.Lock()
		_, _ = s.getMyConsensus(epoch)
		s.Unlock()
		s.state = stateAcceptSignature
	}
	each(func(from, to *state) {
		mine, ok := from.myconsensus[epoch]
		if !ok {
			return
		}
		fpk := pkOf(from)
		sig, ok := mine.Signatures[fpk]
		require.True(ok)
		serialized, err := sig.Marshal()
		require.NoError(err)
		signed, err := cert.Sign(from.s.identityPrivateKey, from.s.identityPublicKey, serialized, epoch)
		require.NoError(err)
		to.onSigUpload(&commands.Sig{Epoch: epoch, PublicKey: from.s.identityPublicKey, Payload: signed}, fpk[:])
	})

	docs := map[int]*pki.Document{}
	for i, s := range states {
		s.Lock()
		doc, err := s.getThresholdConsensus(epoch)
		s.Unlock()
		if err == nil {
			docs[i] = doc
		}
	}
	return states, cfgs, epoch, docs
}

func TestPartitionEvenSplitMakesNoConsensus(t *testing.T) {
	_, _, _, docs := runPartitionedRound(t, 4, [][]int{{0, 1}, {2, 3}})
	require.Empty(t, docs, "a 2/2 split of four authorities must not reach a threshold consensus")
}

func TestPartitionMajorityFinalisesAndMinorityHeals(t *testing.T) {
	cases := []string{"Ed25519", "Ed25519 Sphincs+"}
	if testing.Short() {
		cases = cases[:1]
	}
	saved := testSignatureScheme
	defer func() { testSignatureScheme = saved }()
	for _, name := range cases {
		t.Run(name, func(t *testing.T) {
			testSignatureScheme = signSchemes.ByName(name)
			require.NotNil(t, testSignatureScheme)
			testPartitionMajorityHeals(t)
		})
	}
}

func testPartitionMajorityHeals(t *testing.T) {
	require := require.New(t)
	states, cfgs, epoch, docs := runPartitionedRound(t, 5, [][]int{{0, 1, 2}, {3, 4}})
	require.Len(docs, 3, "the majority must finalise")
	for _, i := range []int{3, 4} {
		require.NotContains(docs, i, "the minority must not finalise on its own")
	}
	want := docs[0].Sum256()
	for _, i := range []int{1, 2} {
		require.Equal(want, docs[i].Sum256(), "the majority forked")
	}

	majority, minority := states[0], states[3]
	majority.serializedDocsMu.Lock()
	raw := majority.serializedDocs[epoch]
	majority.serializedDocsMu.Unlock()
	require.NotEmpty(raw)

	idScheme := testSignatureScheme
	_, majLink, err := testingScheme.GenerateKeyPair()
	require.NoError(err)
	_, minLink, err := testingScheme.GenerateKeyPair()
	require.NoError(err)
	majCfg := &wire.SessionConfig{
		KEMScheme: testingScheme, PKISignatureScheme: idScheme,
		Authenticator: acceptAuthenticator{}, AdditionalData: []byte(cfgs[0].Server.Identifier),
		AuthenticationKey: majLink, RandomReader: rand.Reader,
	}
	minCfg := &wire.SessionConfig{
		KEMScheme: testingScheme, PKISignatureScheme: idScheme,
		Authenticator: acceptAuthenticator{}, AdditionalData: []byte(cfgs[3].Server.Identifier),
		AuthenticationKey: minLink, RandomReader: rand.Reader,
	}
	majSess, err := wire.NewPKISession(majCfg, false)
	require.NoError(err)
	minSess, err := wire.NewPKISession(minCfg, true)
	require.NoError(err)
	minConn, majConn := net.Pipe()
	t.Cleanup(func() { _ = minConn.Close() })
	t.Cleanup(func() { _ = majConn.Close() })
	ea := make(chan error, 1)
	go func() { ea <- majSess.Initialize(context.Background(), majConn) }()
	require.NoError(minSess.Initialize(context.Background(), minConn))
	require.NoError(<-ea)
	go func() {
		for {
			cmd, err := majSess.RecvCommand(context.Background())
			if err != nil {
				return
			}
			if _, ok := cmd.(*commands.GetConsensus); ok {
				_ = majSess.SendCommand(context.Background(), &commands.Consensus{ErrorCode: commands.ConsensusOk, Payload: raw})
			}
		}
	}()

	var peer *config.Authority
	for _, a := range cfgs[3].Authorities {
		if a.IdentityPublicKey.Equal(majority.s.identityPublicKey) {
			peer = a
		}
	}
	require.NotNil(peer)
	minority.hasIPv4 = true
	minority.s.cfg.Server.PersistentPeerConns = true
	minority.s.cfg.Authorities = []*config.Authority{peer}
	pc := minority.peerConnFor(peer.Identifier)
	pc.session, pc.conn = minSess, minConn

	minority.Lock()
	minority.backgroundFetchConsensus(epoch)
	minority.Unlock()
	require.Eventually(func() bool {
		minority.RLock()
		defer minority.RUnlock()
		d, ok := minority.documents[epoch]
		return ok && d.Sum256() == want
	}, 30*time.Second, 50*time.Millisecond, "the minority did not take the majority's consensus after healing")
}

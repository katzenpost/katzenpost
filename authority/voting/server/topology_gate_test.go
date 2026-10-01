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

func TestFixupAndValidateDerivesLayersFromPinnedTopology(t *testing.T) {
	require := require.New(t)
	_, cfgs, err := genVotingAuthoritiesCfg(&config.Parameters{Mu: 0.001}, 1)
	require.NoError(err)
	cfg := cfgs[0]
	cfg.Topology = &config.Topology{Layers: make([]config.Layer, 2)}
	cfg.Server.WireKEMScheme = "x25519"

	cfg.Debug.Layers = 0
	require.NoError(cfg.FixupAndValidate(true))
	require.Equal(2, cfg.Debug.Layers, "an unset Layers takes the pinned topology's layer count")
}

func TestFixupAndValidateRejectsLayerCountMismatch(t *testing.T) {
	require := require.New(t)
	_, cfgs, err := genVotingAuthoritiesCfg(&config.Parameters{Mu: 0.001}, 1)
	require.NoError(err)
	cfg := cfgs[0]
	cfg.Topology = &config.Topology{Layers: make([]config.Layer, 2)}
	cfg.Debug.Layers = 3

	err = cfg.FixupAndValidate(true)
	require.Error(err)
	require.Contains(err.Error(), "Layers is 3 but the configured Topology has 2 layers")
}

// MinNodesPerLayer is the authority's own configured floor on how many mixes a
// layer must hold (config.Debug), and nothing applies it per epoch: verifyTopology
// enforces it but no caller reaches it. mixnet.md requires the layered topology
// this rests on. Every layer of the scenario topology holds two
// mixes, so withholding one mix descriptor leaves exactly one layer short
// while the document stays well formed by IsDocumentWellFormed's weaker rule.
func TestGetMyConsensusRefusesTopologyBelowMinimum(t *testing.T) {
	require := require.New(t)
	epoch, _, _ := epochtime.Now()
	epoch = epoch + 2
	states, _ := buildScenarioStates(t, 3, epoch, nil)

	var dropped [hash.HashSize]byte
	for pk := range states[0].authorizedMixes {
		dropped = pk
		break
	}
	require.NotEqual([hash.HashSize]byte{}, dropped, "the scenario must authorize at least one mix")

	for _, s := range states {
		s.s.cfg.Debug.MinNodesPerLayer = 2
		delete(s.descriptors[epoch], dropped)
		delete(s.authorizedMixes, dropped)
	}

	for i, s := range states {
		s.votingEpoch = epoch
		s.genesisEpoch = epoch
		myVote, err := s.getVote(epoch)
		require.NoError(err)
		s.state = stateAcceptVote
		for j, a := range states {
			if j == i {
				continue
			}
			a.Lock()
			a.votes[epoch][hash.Sum256From(s.s.identityPublicKey)] = myVote
			a.Unlock()
		}
	}

	for i, s := range states {
		s.state = stateAcceptReveal
		c := s.reveal(epoch)
		for j, a := range states {
			if j == i {
				continue
			}
			a.Lock()
			a.reveals[epoch][hash.Sum256From(s.s.identityPublicKey)] = c
			a.Unlock()
		}
	}

	for i, s := range states {
		s.Lock()
		s.state = stateAcceptCert
		myCertificate, err := s.getCertificate(epoch)
		require.NoError(err)
		_, err = pki.SignDocument(s.s.identityPrivateKey, s.s.identityPublicKey, myCertificate)
		require.NoError(err)
		for j, a := range states {
			if j == i {
				continue
			}
			a.Lock()
			a.certificates[epoch][hash.Sum256From(s.s.identityPublicKey)] = myCertificate
			a.Unlock()
		}
		s.Unlock()
	}

	for _, s := range states {
		s.Lock()
		doc, err := s.getMyConsensus(epoch)
		s.Unlock()
		require.Error(err, "a consensus with a layer below MinNodesPerLayer must not be signed")
		require.Contains(err.Error(), "below the configured topology minimum")
		require.Nil(doc)
	}
}

func TestGetMyConsensusSignsAtTheConfiguredMinimum(t *testing.T) {
	require := require.New(t)
	epoch, _, _ := epochtime.Now()
	epoch = epoch + 2
	states, _ := buildScenarioStates(t, 3, epoch, nil)

	for _, s := range states {
		s.s.cfg.Debug.MinNodesPerLayer = 2
	}

	for i, s := range states {
		s.votingEpoch = epoch
		s.genesisEpoch = epoch
		myVote, err := s.getVote(epoch)
		require.NoError(err)
		s.state = stateAcceptVote
		for j, a := range states {
			if j == i {
				continue
			}
			a.Lock()
			a.votes[epoch][hash.Sum256From(s.s.identityPublicKey)] = myVote
			a.Unlock()
		}
	}

	for i, s := range states {
		s.state = stateAcceptReveal
		c := s.reveal(epoch)
		for j, a := range states {
			if j == i {
				continue
			}
			a.Lock()
			a.reveals[epoch][hash.Sum256From(s.s.identityPublicKey)] = c
			a.Unlock()
		}
	}

	for i, s := range states {
		s.Lock()
		s.state = stateAcceptCert
		myCertificate, err := s.getCertificate(epoch)
		require.NoError(err)
		_, err = pki.SignDocument(s.s.identityPrivateKey, s.s.identityPublicKey, myCertificate)
		require.NoError(err)
		for j, a := range states {
			if j == i {
				continue
			}
			a.Lock()
			a.certificates[epoch][hash.Sum256From(s.s.identityPublicKey)] = myCertificate
			a.Unlock()
		}
		s.Unlock()
	}

	for _, s := range states {
		s.Lock()
		doc, err := s.getMyConsensus(epoch)
		s.Unlock()
		require.NoError(err)
		require.NotNil(doc)
		require.Len(doc.Topology, 3)
		for layer, nodes := range doc.Topology {
			require.GreaterOrEqual(len(nodes), 2, "layer %d", layer)
		}
	}
}

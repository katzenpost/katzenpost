// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/hpqc/hash"

	"github.com/katzenpost/katzenpost/authority/voting/server/config"
	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/pki"
)

func populatedLayers(n, perLayer int) []config.Layer {
	layers := make([]config.Layer, n)
	for i := range layers {
		layers[i].Nodes = make([]config.Node, perLayer)
		for j := range layers[i].Nodes {
			layers[i].Nodes[j].Identifier = fmt.Sprintf("layer%d-node%d", i, j)
		}
	}
	return layers
}

func TestFixupAndValidateDerivesLayersFromPinnedTopology(t *testing.T) {
	require := require.New(t)
	_, cfgs, err := genVotingAuthoritiesCfg(&config.Parameters{Mu: 0.001}, 1)
	require.NoError(err)
	cfg := cfgs[0]
	cfg.Topology = &config.Topology{Layers: populatedLayers(2, 2)}
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
	cfg.Topology = &config.Topology{Layers: populatedLayers(2, 2)}
	cfg.Debug.Layers = 3

	err = cfg.FixupAndValidate(true)
	require.Error(err)
	require.Contains(err.Error(), "Layers is 3 but the configured Topology has 2 layers")
}

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

func TestConfigRefusesLayerBelowMinNodesPerLayer(t *testing.T) {
	require := require.New(t)

	build := func(perLayer, minPerLayer int) *config.Config {
		_, cfgs, err := genVotingAuthoritiesCfg(&config.Parameters{Mu: 0.001}, 1)
		require.NoError(err)
		cfg := cfgs[0]
		cfg.Topology = &config.Topology{Layers: populatedLayers(2, perLayer)}
		cfg.Debug.Layers = 2 // agree with the pinned topology, so the floor is what fires
		cfg.Debug.MinNodesPerLayer = minPerLayer
		cfg.Server.WireKEMScheme = "x25519"
		return cfg
	}

	err := build(1, 2).FixupAndValidate(true)
	require.Error(err, "a layer below the configured minimum must be refused")
	require.Contains(err.Error(), "fewer than MinNodesPerLayer 2")

	require.NoError(build(2, 2).FixupAndValidate(true), "a layer at the minimum must be accepted")

	err = build(1, 0).FixupAndValidate(true)
	require.Error(err, "an unset minimum must resolve to the default, not to zero")
	require.Contains(err.Error(), "fewer than MinNodesPerLayer 2")
}

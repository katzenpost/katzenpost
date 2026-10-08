// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/authority/voting/server/config"
	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/core/pki"
)

func TestGenerateTopologyPriorHasMoreLayers(t *testing.T) {
	lb, err := log.New("", "ERROR", false)
	require.NoError(t, err)
	st := &state{
		log: lb.GetLogger("topology-audit"),
		s:   &Server{cfg: &config.Config{Debug: &config.Debug{Layers: 2}}},
	}

	nodes := make([]*pki.MixDescriptor, 0, 6)
	for i := 0; i < 6; i++ {
		nodes = append(nodes, fakeMixDesc(byte(i+1)))
	}
	prior := &pki.Document{
		Topology: [][]*pki.MixDescriptor{
			{nodes[0], nodes[1]},
			{nodes[2], nodes[3]},
			{nodes[4], nodes[5]},
		},
	}
	srv := make([]byte, 32)

	require.NotPanics(t, func() {
		topo := st.generateTopology(nodes, prior, srv)
		require.Len(t, topo, 2, "topology must have cfg.Debug.Layers layers")
		total := 0
		for _, l := range topo {
			total += len(l)
		}
		require.Equal(t, len(nodes), total, "every node must be placed")
	}, "generateTopology must not panic when the prior document has more layers than cfg.Debug.Layers")
}

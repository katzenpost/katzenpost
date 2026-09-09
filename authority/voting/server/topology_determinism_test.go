// SPDX-FileCopyrightText: © 2026 Jacob Appelbaum
// SPDX-License-Identifier: AGPL-3.0-only

package server

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/katzenpost/katzenpost/authority/voting/server/config"
	"github.com/katzenpost/katzenpost/core/log"
	"github.com/katzenpost/katzenpost/core/pki"
)

func fakeMixDesc(id byte) *pki.MixDescriptor {
	return &pki.MixDescriptor{IdentityKey: []byte{id, id, id, id}}
}

func topologyFingerprint(topo [][]*pki.MixDescriptor) string {
	var b strings.Builder
	for _, layer := range topo {
		for _, n := range layer {
			b.Write(n.IdentityKey)
			b.WriteByte('|')
		}
		b.WriteByte(';')
	}
	return b.String()
}

// TestGenerateTopologyDeterministic guards the byte-identical-consensus
// invariant for the churn-minimizing topology path: generateTopology flattens
// a map (random iteration order per call) but sorts the pending nodes by
// public key before the srv-seeded permutation, so repeated calls with the
// same inputs must produce identical topology. If the sort were dropped, Go's
// randomized map iteration would make the two calls differ.
func TestGenerateTopologyDeterministic(t *testing.T) {
	lb, err := log.New("", "DEBUG", false)
	require.NoError(t, err)
	st := &state{
		log: lb.GetLogger("topology-test"),
		s: &Server{
			cfg: &config.Config{Debug: &config.Debug{Layers: 3}},
		},
	}

	nodes := make([]*pki.MixDescriptor, 0, 9)
	for i := 0; i < 9; i++ {
		nodes = append(nodes, fakeMixDesc(byte(i+1)))
	}
	prior := &pki.Document{
		Topology: [][]*pki.MixDescriptor{
			{nodes[0], nodes[1], nodes[2]},
			{nodes[3], nodes[4], nodes[5]},
			{nodes[6], nodes[7], nodes[8]},
		},
	}
	srv := make([]byte, 32)

	first := topologyFingerprint(st.generateTopology(nodes, prior, srv))
	for i := 0; i < 8; i++ {
		require.Equal(t, first, topologyFingerprint(st.generateTopology(nodes, prior, srv)),
			"generateTopology is not deterministic across calls")
	}
}

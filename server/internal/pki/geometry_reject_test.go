// SPDX-License-Identifier: AGPL-3.0-only

package pki

import (
	"testing"

	"github.com/stretchr/testify/require"

	nikeschemes "github.com/katzenpost/hpqc/nike/schemes"

	"github.com/katzenpost/katzenpost/core/epochtime"
	"github.com/katzenpost/katzenpost/core/log"
	cpki "github.com/katzenpost/katzenpost/core/pki"
	"github.com/katzenpost/katzenpost/core/sphinx/geo"
	"github.com/katzenpost/katzenpost/server/config"
	"github.com/katzenpost/katzenpost/server/internal/glue"
	"github.com/katzenpost/katzenpost/server/internal/pkicache"
)

type geometryGlue struct {
	glue.Glue
	cfg *config.Config
}

func (g *geometryGlue) Config() *config.Config { return g.cfg }

func TestRejectForeignGeometry(t *testing.T) {
	backend, err := log.New("", "ERROR", false)
	require.NoError(t, err)

	nike := nikeschemes.ByName("x25519")
	local := geo.GeometryFromUserForwardPayloadLength(nike, 2000, true, 5)
	foreign := geo.GeometryFromUserForwardPayloadLength(nike, 3000, true, 5)
	require.NotEqual(t, local.Hash(), foreign.Hash())

	p := &pki{
		glue:          &geometryGlue{cfg: &config.Config{SphinxGeometry: local}},
		log:           backend.GetLogger("pki"),
		docs:          make(map[uint64]*pkicache.Entry),
		rawDocs:       make(map[uint64][]byte),
		failedFetches: make(map[uint64]error),
	}

	epoch, _, _ := epochtime.Now()

	require.True(t, p.rejectForeignGeometry(epoch, &cpki.Document{Epoch: epoch, SphinxGeometryHash: foreign.Hash()}))
	failed, err := p.getFailedFetch(epoch)
	require.True(t, failed)
	require.ErrorIs(t, err, errSphinxGeometryMismatch)

	require.False(t, p.rejectForeignGeometry(epoch+1, &cpki.Document{Epoch: epoch + 1, SphinxGeometryHash: local.Hash()}))
	failed, err = p.getFailedFetch(epoch + 1)
	require.False(t, failed)
	require.NoError(t, err)
}
